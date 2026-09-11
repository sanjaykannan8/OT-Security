##! SIH26145 passive sensor policy: file analysis of mounted PCAPs only (`zeek -r`).
##! Base scripts (conn, dns, ssl, weird, ...) are loaded by default. No capture interface, no active
##! components, no payload extraction, no TLS decryption.

@load policy/protocols/ssl/validate-certs
@load ./flow-update

redef LogAscii::use_json = T;

# Fixtures are generated with correct checksums; captures with offloaded checksums would otherwise be
# dropped silently.
redef ignore_checksums = T;

redef Site::local_nets += { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 };

# Keep the log set small: only conn, dns, ssl, weird and flow_update cross the link.
event zeek_init() &priority=-10
	{
	Log::disable_stream(Files::LOG);
	Log::disable_stream(X509::LOG);
	}
