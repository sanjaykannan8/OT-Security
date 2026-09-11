# Passive sensor image: Zeek reading mounted PCAP files. No capture interface, no capabilities needed.
FROM zeek/zeek:8.0.10

RUN groupadd -g 10001 sih && useradd -u 10001 -g sih -M -s /usr/sbin/nologin sih \
 && mkdir -p /data/zeek-logs /opt/sih/zeek && chown sih:sih /data/zeek-logs

COPY sensor/zeek/local.zeek sensor/zeek/flow-update.zeek sensor/zeek/replay.sh /opt/sih/zeek/
RUN chmod 0755 /opt/sih/zeek/replay.sh && zeek -a /opt/sih/zeek/local.zeek

USER 10001
WORKDIR /data/zeek-logs
ENTRYPOINT ["/opt/sih/zeek/replay.sh"]
CMD ["all"]
