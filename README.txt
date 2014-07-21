sdn_sensor

Creator: Matthew Hall <mhall@mhcomputing.net>

SDN (Intel DPDK) based threat intelligence event sensor

Features:

1) Syslog Processing

PCRE Chain

syslog-ng trie

2) Raw traffic Processing

CIDR Table

PCAP Chain

3) sFlow Processing

4) NetFlow / IPFIX Processing

Coding Standards:

1) Use 4 spaces for all indent levels.

2) Don't bother with 80-character lines, just make it readable.

3) The "standard name prefix" for functions / globals is "ss_" (short for 
sdn_sensor)

4) Lots of compiler warnings are on by default. The clang scan-build tool will 
find even more bugs.
