##! Bounded periodic cumulative snapshots of live connections (flow_update.log).
##!
##! Zeek normally logs a connection only when it ends. Sustained-flow detectors (exfiltration, floods)
##! need earlier visibility, so every connection that has carried payload is polled every
##! FlowUpdate::poll_interval and its cumulative counters are logged. Snapshots are capped per second of
##! network time; drops are counted in FlowUpdate::dropped_updates. The SOC converts cumulative values to
##! deltas exactly once (see flink/sih_detect/flowdelta.py).

@load base/protocols/conn

module FlowUpdate;

export {
	redef enum Log::ID += { LOG };

	## Interval between snapshots of one connection.
	const poll_interval: interval = 5 sec &redef;

	## Upper bound on snapshots written per second of network time.
	const max_updates_per_second: count = 2000 &redef;

	type Info: record {
		ts: time &log;
		uid: string &log;
		id: conn_id &log;
		proto: transport_proto &log;
		service: string &log &optional;
		duration: interval &log;
		orig_bytes: count &log &optional;
		resp_bytes: count &log &optional;
		orig_pkts: count &log &optional;
		resp_pkts: count &log &optional;
		orig_ip_bytes: count &log &optional;
		resp_ip_bytes: count &log &optional;
		history: string &log &optional;
		snapshot_seq: count &log;
		snapshot_interval: interval &log;
	};

	global dropped_updates: count = 0;
}

global rate_second: time = double_to_time(0.0);
global rate_count: count = 0;

event zeek_init() &priority=5
	{
	Log::create_stream(FlowUpdate::LOG, [$columns=Info, $path="flow_update"]);
	}

function snapshot(c: connection, cnt: count): interval
	{
	# Connections that have not carried payload (e.g. unanswered SYNs) are not snapshotted.
	if ( c$orig$size == 0 && c$resp$size == 0 )
		return poll_interval;

	local now = network_time();
	local sec = double_to_time(floor(time_to_double(now)));
	if ( sec != rate_second )
		{
		rate_second = sec;
		rate_count = 0;
		}
	if ( rate_count >= max_updates_per_second )
		{
		++dropped_updates;
		return poll_interval;
		}
	++rate_count;

	local rec = Info($ts=now, $uid=c$uid, $id=c$id, $proto=get_port_transport_proto(c$id$resp_p),
	                 $duration=now - c$start_time, $snapshot_seq=cnt + 1, $snapshot_interval=poll_interval);
	if ( |c$service| > 0 )
		rec$service = join_string_set(c$service, ",");
	rec$orig_bytes = c$orig$size;
	rec$resp_bytes = c$resp$size;
	if ( c$orig?$num_pkts )
		rec$orig_pkts = c$orig$num_pkts;
	if ( c$resp?$num_pkts )
		rec$resp_pkts = c$resp$num_pkts;
	if ( c$orig?$num_bytes_ip )
		rec$orig_ip_bytes = c$orig$num_bytes_ip;
	if ( c$resp?$num_bytes_ip )
		rec$resp_ip_bytes = c$resp$num_bytes_ip;
	if ( c?$history )
		rec$history = c$history;
	Log::write(FlowUpdate::LOG, rec);
	return poll_interval;
	}

event new_connection(c: connection)
	{
	ConnPolling::watch(c, snapshot, 0, poll_interval);
	}

event zeek_done()
	{
	if ( dropped_updates > 0 )
		Reporter::warning(fmt("flow_update snapshots dropped by rate cap: %d", dropped_updates));
	}
