# sdn_sensor #

SDN (Intel DPDK) based threat intelligence sensor in C99,
with accompanying security event analytics stack in Java

Creator: Matthew Hall <mhall@mhcomputing.net>

Available under the MIT License.

## Summary, aka tl;dr ##

The sdn_sensor is a user-mode security-aware TCP/IP network stack, which 
performs threat intelligence analysis of raw traffic, DNS packets, NetFlow / 
IPFIX, sFlow, and TCP and UDP Syslog protocols.

All traffic inspection results are processed using event correlation, 
aggregation, deduplication, summarization, charting, reporting, and logging, 
as part of a high performance analytics stack, which is capable of handling 
300,000 or more events per second, even in a laptop system.

The sdn_sensor is intended to help the security community bridge the gap 
between network hardware which can handle 10-100 gigabits/sec and 1,000,000 
connections per second, and modern SIM (security information management) 
collectors and correlation systems, which usually only handle 100,000 logs per 
second in the best case, and cost $100,000 or more.

## Up and Running With Vagrant ##

Get vagrant: [Vagrant Downloads (https://www.vagrantup.com/downloads.html) .

1. `vagrant up`
2. `vagrant ssh`
3. `cd /vagrant`
4. Edit `conf/sdn_sensor_vagrant.example`. The Vagrant provisioning will copy 
it to `sdn_sensor_vagrant.json` and subsitute some per-VM values into place. 
In particular the user should set `{ipv4,ipv6}_{address,gateway}`, `log_level` 
(if debugging), `ioc_files / path`.
5. Add some of your own threat intelligence to the `ioc_file`. The ioc_file 
   CSV fields are:
       id (64-bit integer),type (ip, domail, url, email), threat_type / itype (free-form string), ip (optional), dns, ioc_value
6. `cd src`
7. `make clean; make`
8. `sudo ../scripts/sdn_sensor.bash`. (Use `-d` to load it in gdb.) Init
   and log messages from the sensor will appear on the console.
9. `scripts/nn-receiver.pl` will show the sensor logs. They are JSON-format
   messages routed through `nanomsg`, which is a native C, Berkeley Socket 
   like MQ library based upon, and simplified from, ZeroMQ. nanomsg has many 
   language bindings, including a Java language binding, which is used by
   the included analytics stack to receive messages from the sdn_sensor core.
10. `scripts/sloccount.bash` will show the lines of code and US-dollar value 
   and time / schedule needed to develop all of the code.

## Design Philosophy ##

The sdn_sensor is designed around the assumption that every large network 
already contains malicious traffic, compromised systems, malware, and APTs 
(Advanced Persistent Threats). Usually these arrive via diverse sources, such 
as email, mobile devices, BYOD (bring your own device), open / share network 
resources (such as SANs, file sharing, etc.), user error, software defects, 
etc.

Even the US SEC (United States Securities and Exchange Commission) has adopted 
this assumption. Since 2011, the SEC requires publicly-traded US corporations 
to report their cybersecurity risks which could have a material impact on 
their securities.

In the face of this new reality we are all trying to figure out what to do! It 
seems somewhat pointless to try to filter the traffic for specific exploits or 
signatures, or to assume firewall or IPS rules will actually prevent much of 
anything.

Instead, the sdn_sensor is based on the idea that it makes more sense to try 
to detect the activity that is surely already happening rather than prevent 
the apparently unpreventable. To accomplish this, several knowledge sources 
and technologies are combined in a single codebase:

* Threat Intelligence IOCs (Indicators of Compromise), such as known malicious 
  IPs, DNS Domains, URLs, Email Addresses, and File Hashes,
* SDN-based (software defined networking) user-space packet processing, which 
  allows many gigabits per second of traffic or management metadata to be 
  inspected at line rate, based on Intel DPDK (Data Plane Development Kit),
* high-bandwidth low-latency message queueing, used for years in stock markets 
  and other major world financial transaction processing systems,
* low-latency in-memory streaming database, ESP (event stream processing), and 
  CEP (complex event processing) engines, designed to dig through huge volumes 
  of event haystacks to find the needles of valuable data, originally used in 
  HFT (high-frequency trading in financial markets)

The sdn_sensor leverages the talents and achievements of these communities:

* the intelligence community,
* the information security community,
* the network hardware community,
* the financial markets community,

By integrating the amazing things these communities have created, the 
sdn_sensor can successfully detect malicious activities already in progress, 
and allow monitoring, incident response, and remediation as issues arise, even 
in the face of the numerous technical challenges.

## Technical Details ##

IOC matching in the sdn_sensor is performed against the following areas:

* packet headers from IPv4, IPv6, TCP, and UDP,
* DNS question and answer contents,
* flow records from NetFlow, IPFIX, or sFlow,
* UDP and TCP based Syslog (an O(n) regex engine is used to extract tokens 
  which appear to be IOCs from inside the text of the log messages).

In addition to these, it is possible to perform matching with:
* libpcap filter expressions,
* CIDR blocks in IPv4 or IPv6,
* DNS names or IPs inside DNS questions and answers.

## Coding Standards ##

1) Use 4 spaces for all indent levels.

2) Don't bother with 80-character lines, just make it readable.

3) The "standard name prefix" for functions / globals is "ss_" (short for 
sdn_sensor).

4) Lots of compiler warnings are on by default. The clang scan-build tool will 
find even more bugs.

5) Don't use messy or complicated code that is hard to debug.

6) Mark any questionable, hacked, known-buggy or otherwise suspect code with 
XXX so other people can find it and fix it. It doesn't have to be perfect 
right away but don't lie to the person who comes after you.

7) Use a lot of log messages as this is young software with bugs.

8) put `filename: one-line description` on every git commit message.

9) Use well known best-in-class dependency libraries. Follow the principle of 
least surprise as much as possible. Try to make git submodules for the 
dependencies so it's easy to track and update them.

10) Allocate all memory using DPDK or `libjemalloc`. Don't use the `libc` 
allocator, because it is way too slow and buggy. Remember many `string.h` 
functions call libc alloc secretly. This will cause segfaults if pointers get 
mixed between `libjemalloc` and `libc`. To avoid this reimplement any broken 
functions in `je_utils.c`.

11) Use the `make cproto` command to auto-update the function prototypes, it 
makes life easy. Use `scripts/create-header-file.pl` to make new blank header 
files in the right format to work with `make cproto`.

## SECURITY NOTICES ##

*THIS IS ALPHA CODE, WITH BASIC QA TESTING ONLY!!!*

*WARNING*: DPDK more or less directly or indirectly allows the code to read 
and write any arbitrary addresses in system memory whatsoever without any 
restrictions.

Fundamentally DPDK allows Bus Mater and DMA (direct memory access) by the NIC 
(network interface card) by design. This means that PCIe (PCI Express) bus on 
the motherboard permits almost unlimited read and write access to all of 
system memory, user-space or kernel-space, or any other region(s) present.

Some effort is taken to ensure no obvious vulnerabilities are present using 
Coverity, but this is early code, and it has a ton of complex network stack 
logic, using raw C pointer manipulation. Definitely don't try to run this on 
any sensitive or trusted machines.

With virtualization it is safer, as it should only be able to take over the 
VM, and not the hypervisor. However if you use native PCI Passthrough, or 
other raw or low level VF (Virtual Functions) on the NICs, or special DPDK 
Ethernet drivers, anything could happen. Think carefully.

### Coverity Scan Static Analysis Results ###

<a href="https://scan.coverity.com/projects/2908">
<img src="https://scan.coverity.com/projects/2908/badge.svg"
     alt="Coverity Scan Build Status" />
</a>
