package net.mhcomputing.sdn_sensor.types;

import java.util.Date;

import net.mhcomputing.sdn_sensor.threats.Connection;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.util.ISO8601Utils;

public class LogMessage {
    private long       timeMillis;
    private String     sensorName;
    private short      portId;
    private LogType    source;
    private boolean    isSelf;
    private long       seqNum;
    
    private Connection connection;
    
    private String     agentIp;
    private long       bytes;
    private long       packets;
    private long       crc32;
    private int        dstIfIndex;
    private int        srcIfIndex;
    private String     dstIp;
    private String     srcIp;
    private Direction  direction;
    private String     dstMac;
    private String     srcMac;
    private String     dnsName;
    private int        dstPort;
    private int        srcPort;
    private int        dstAsn;
    private int        srcAsn;
    private int        dstCidrMask;
    private int        srcCidrMask;
    // XXX: verify if these are right
    private String     engineId;
    private String     engineType;
    private short      ethType;
    // XXX: not sure if flow sec is summed w/ usec
    private long       flowSec;
    private long       flowUsec;
    private long       flowStartSec;
    private long       flowStartMsec;
    private long       flowStopSec;
    private long       flowStopMsec;
    private String     gatewayIp;
    private int        icmpType;
    private int        icmpCode;
    private short      ipProtocol;
    private short      ipTos;
    private short      ipTtl;
    private short      tcpFlags;
    private IocType    iocType;
    private String     iocValue;
    private String     iocDns;
    private long       iocFileId;
    private long       iocId;
    private String     iocIp;
    private String     iocThreatType;
    private int        l4Length;
    private int        length;
    private String     message;
    private int        netflowVersion;
    private int        sourceId;
    private long       sysTimeSec;
    private int        sysTimeNsec;
    private long       sysUpTimeSec;
    private long       sysUpTimeMsec;
    private int        tag;
    
    @JsonIgnore
    public long getTimeMillis() {
        return timeMillis;
    }
    @JsonProperty("time")
    public Date getTime() {
        return new Date(timeMillis);
    }
    @JsonProperty("time")
    public void setTimeMillis(long receiveTime) {
        this.timeMillis = receiveTime;
    }
    
    @JsonProperty("sensor")
    public String getSensorName() {
        return sensorName;
    }
    @JsonProperty("sensor")
    public void setSensorName(String sensorName) {
        this.sensorName = sensorName;
    }
    
    @JsonProperty("port_id")
    public short getPortId() {
        return portId;
    }
    @JsonProperty("port_id")
    public void setPortId(short portId) {
        this.portId = portId;
    }
    
    @JsonProperty("source")
    public LogType getSource() {
        return source;
    }
    @JsonProperty("source")
    public void setSource(LogType source) {
        this.source = source;
    }
    
    @JsonProperty("self")
    public boolean isSelf() {
        return isSelf;
    }
    @JsonProperty("self")
    public void setSelf(boolean isSelf) {
        this.isSelf = isSelf;
    }
    
    @JsonProperty("seq_num")
    public long getSeqNum() {
        return seqNum;
    }
    @JsonProperty("seq_num")
    public void setSeqNum(long seqNum) {
        this.seqNum = seqNum;
    }
    
    @JsonProperty("hash_key")
    public String getHashKey() {
        if (connection == null) {
            return Connection.EMPTY;
        }
        return connection.getHashKey();
    }
    
    @JsonIgnore
    public Connection getConnection() {
        return connection;
    }
    @JsonIgnore
    public void setConnection(Connection connection) {
        this.connection = connection;
    }
    
    @JsonProperty("agentip")
    public String getAgentIp() {
        return agentIp;
    }
    @JsonProperty("agentip")
    public void setAgentIp(String agentIp) {
        this.agentIp = agentIp;
    }
    
    @JsonProperty("bytes")
    public long getBytes() {
        return bytes;
    }
    @JsonProperty("bytes")
    public void setBytes(long bytes) {
        this.bytes = bytes;
    }
    
    @JsonProperty("packets")
    public long getPackets() {
        return packets;
    }
    @JsonProperty("packets")
    public void setPackets(long packets) {
        this.packets = packets;
    }
    
    @JsonProperty("crc32")
    public long getCrc32() {
        return crc32;
    }
    @JsonProperty("crc32")
    public void setCrc32(long crc32) {
        this.crc32 = crc32;
    }
    
    @JsonProperty("difindex")
    public int getDstIfIndex() {
        return dstIfIndex;
    }
    @JsonProperty("difindex")
    public void setDstIfIndex(int dstIfIndex) {
        this.dstIfIndex = dstIfIndex;
    }
    
    @JsonProperty("sifindex")
    public int getSrcIfIndex() {
        return srcIfIndex;
    }
    @JsonProperty("sifindex")
    public void setSrcIfIndex(int srcIfIndex) {
        this.srcIfIndex = srcIfIndex;
    }
    
    @JsonProperty("dip")
    public String getDstIp() {
        return dstIp;
    }
    @JsonProperty("dip")
    public void setDstIp(String dstIp) {
        this.dstIp = dstIp;
    }
    
    @JsonProperty("sip")
    public String getSrcIp() {
        return srcIp;
    }
    @JsonProperty("sip")
    public void setSrcIp(String srcIp) {
        this.srcIp = srcIp;
    }
    
    @JsonProperty("direction")
    public Direction getDirection() {
        return direction;
    }
    @JsonProperty("direction")
    public void setDirection(Direction direction) {
        this.direction = direction;
    }
    
    @JsonProperty("dmac")
    public String getDstMac() {
        return dstMac;
    }
    @JsonProperty("dmac")
    public void setDstMac(String dstMac) {
        this.dstMac = dstMac;
    }
    
    @JsonProperty("smac")
    public String getSrcMac() {
        return srcMac;
    }
    @JsonProperty("smac")
    public void setSrcMac(String srcMac) {
        this.srcMac = srcMac;
    }
    
    @JsonProperty("dns_name")
    public String getDnsName() {
        return dnsName;
    }
    @JsonProperty("dns_name")
    public void setDnsName(String dns) {
        this.dnsName = dns;
    }
    
    @JsonProperty("dport")
    public int getDstPort() {
        return dstPort;
    }
    @JsonProperty("dport")
    public void setDstPort(int dstPort) {
        this.dstPort = dstPort;
    }
    
    @JsonProperty("sport")
    public int getSrcPort() {
        return srcPort;
    }
    @JsonProperty("sport")
    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }
    
    @JsonProperty("dst_as")
    public int getDstAsn() {
        return dstAsn;
    }
    @JsonProperty("dst_as")
    public void setDstAsn(int dstAsn) {
        this.dstAsn = dstAsn;
    }
    
    @JsonProperty("src_as")
    public int getSrcAsn() {
        return srcAsn;
    }
    @JsonProperty("src_as")
    public void setSrcAsn(int srcAsn) {
        this.srcAsn = srcAsn;
    }
    
    @JsonProperty("dst_masklen")
    public int getDstCidrMask() {
        return dstCidrMask;
    }
    @JsonProperty("dst_masklen")
    public void setDstCidrMask(int dstCidrMask) {
        this.dstCidrMask = dstCidrMask;
    }
    
    @JsonProperty("src_masklen")
    public int getSrcCidrMask() {
        return srcCidrMask;
    }
    @JsonProperty("src_masklen")
    public void setSrcCidrMask(int srcCidrMask) {
        this.srcCidrMask = srcCidrMask;
    }
    
    @JsonProperty("engine_id")
    public String getEngineId() {
        return engineId;
    }
    @JsonProperty("engine_id")
    public void setEngineId(String engineId) {
        this.engineId = engineId;
    }
    
    @JsonProperty("engine_type")
    public String getEngineType() {
        return engineType;
    }
    @JsonProperty("engine_type")
    public void setEngineType(String engineType) {
        this.engineType = engineType;
    }
    
    @JsonProperty("eth_type")
    public short getEthType() {
        return ethType;
    }
    @JsonProperty("eth_type")
    public void setEthType(short ethType) {
        this.ethType = ethType;
    }
    
    @JsonIgnore
    public long getFlowSec() {
        return flowSec;
    }
    @JsonProperty("flow_millis")
    public long getFlowMillis() {
        return Math.round(flowSec * 1000.0 + flowUsec / 1000.0); 
    }
    @JsonProperty("flow_sec")
    public void setFlowSec(long flowSec) {
        this.flowSec = flowSec;
    }
    
    @JsonIgnore
    public long getFlowUsec() {
        return flowUsec;
    }
    @JsonProperty("flow_usec")
    public void setFlowUsec(long flowUsec) {
        this.flowUsec = flowUsec;
    }
    
    @JsonIgnore
    public long getFlowStartSec() {
        return flowStartSec;
    }
    @JsonProperty("flow_start")
    public Date getFlowStart() {
        return new Date(flowStartSec * 1000 + flowStartMsec);
    }
    @JsonProperty("flow_start_sec")
    public void setFlowStartSec(long flowStartSec) {
        this.flowStartSec = flowStartSec;
    }
    
    @JsonIgnore
    public long getFlowStartMsec() {
        return flowStartMsec;
    }
    @JsonProperty("flow_start_msec")
    public void setFlowStartMsec(long flowStartMsec) {
        this.flowStartMsec = flowStartMsec;
    }
    
    @JsonIgnore
    public long getFlowStopSec() {
        return flowStopSec;
    }
    @JsonProperty("flow_stop")
    public Date getFlowStop() {
        return new Date(flowStopSec * 1000 + flowStopMsec);
    }
    @JsonProperty("flow_stop_sec")
    public void setFlowStopSec(long flowStopSec) {
        this.flowStopSec = flowStopSec;
    }
    
    @JsonIgnore
    public long getFlowStopMsec() {
        return flowStopMsec;
    }
    @JsonProperty("flow_stop_msec")
    public void setFlowStopMsec(long flowStopMsec) {
        this.flowStopMsec = flowStopMsec;
    }
    
    @JsonProperty("gatewayip")
    public String getGatewayIp() {
        return gatewayIp;
    }
    @JsonProperty("gatewayip")
    public void setGatewayIp(String gatewayIp) {
        this.gatewayIp = gatewayIp;
    }
    
    @JsonProperty("icmp_type")
    public int getIcmpType() {
        return icmpType;
    }
    @JsonProperty("icmp_type")
    public void setIcmpType(int icmpType) {
        this.icmpType = icmpType;
    }
    
    @JsonProperty("icmp_code")
    public int getIcmpCode() {
        return icmpCode;
    }
    @JsonProperty("icmp_code")
    public void setIcmpCode(int icmpCode) {
        this.icmpCode = icmpCode;
    }
    
    @JsonProperty("ip_protocol")
    public short getIpProtocol() {
        return ipProtocol;
    }
    @JsonProperty("ip_protocol")
    public void setIpProtocol(short ipProtocol) {
        this.ipProtocol = ipProtocol;
    }
    
    @JsonProperty("ip_tos")
    public short getIpTos() {
        return ipTos;
    }
    @JsonProperty("ip_tos")
    public void setIpTos(short ipTos) {
        this.ipTos = ipTos;
    }
    
    @JsonProperty("ip_ttl")
    public short getIpTtl() {
        return ipTtl;
    }
    @JsonProperty("ip_ttl")
    public void setIpTtl(short ipTtl) {
        this.ipTtl = ipTtl;
    }
    
    @JsonProperty("tcp_flags")
    public short getTcpFlags() {
        return tcpFlags;
    }
    @JsonProperty("tcp_flags")
    public void setTcpFlags(short tcpFlags) {
        this.tcpFlags = tcpFlags;
    }
    
    @JsonProperty("type")
    public IocType getIocType() {
        return iocType;
    }
    @JsonProperty("type")
    public void setIocType(IocType iocType) {
        this.iocType = iocType;
    }
    
    @JsonProperty("value")
    public String getIocValue() {
        return iocValue;
    }
    @JsonProperty("value")
    public void setIocValue(String iocValue) {
        this.iocValue = iocValue;
    }
    
    @JsonProperty("dns")
    public String getIocDns() {
        return iocDns;
    }
    @JsonProperty("dns")
    public void setIocDns(String iocDns) {
        this.iocDns = iocDns;
    }
    
    @JsonProperty("file_id")
    public long getIocFileId() {
        return iocFileId;
    }
    @JsonProperty("file_id")
    public void setIocFileId(long iocFileId) {
        this.iocFileId = iocFileId;
    }
    
    @JsonProperty("ioc_id")
    public long getIocId() {
        return iocId;
    }
    @JsonProperty("ioc_id")
    public void setIocId(long iocId) {
        this.iocId = iocId;
    }
    
    @JsonProperty("ip")
    public String getIocIp() {
        return iocIp;
    }
    @JsonProperty("ip")
    public void setIocIp(String iocIp) {
        this.iocIp = iocIp;
    }
    
    @JsonProperty("threat_type")
    public String getIocThreatType() {
        return iocThreatType;
    }
    @JsonProperty("threat_type")
    public void setIocThreatType(String iocThreatType) {
        this.iocThreatType = iocThreatType;
    }
    
    @JsonProperty("l4_length")
    public int getL4Length() {
        return l4Length;
    }
    @JsonProperty("l4_length")
    public void setL4Length(int l4Length) {
        this.l4Length = l4Length;
    }
    
    @JsonProperty("length")
    public int getLength() {
        return length;
    }
    @JsonProperty("length")
    public void setLength(int length) {
        this.length = length;
    }
    
    @JsonProperty("message")
    public String getMessage() {
        return message;
    }
    @JsonProperty("message")
    public void setMessage(String message) {
        this.message = message;
    }
    
    @JsonProperty("netflow_version")
    public int getNetflowVersion() {
        return netflowVersion;
    }
    @JsonProperty("netflow_version")
    public void setNetflowVersion(int netflowVersion) {
        this.netflowVersion = netflowVersion;
    }
    
    @JsonProperty("source_id")
    public int getSourceId() {
        return sourceId;
    }
    @JsonProperty("source_id")
    public void setSourceId(int sourceId) {
        this.sourceId = sourceId;
    }
    
    @JsonIgnore
    public long getSysTimeSec() {
        return sysTimeSec;
    }
    @JsonProperty("sys_time")
    public Date getSysTime() {
        return new Date(Math.round(sysTimeSec * 1000.0 + sysTimeNsec / 1000000.0));
    }
    @JsonProperty("sys_time_sec")
    public void setSysTimeSec(long sysTimeSec) {
        this.sysTimeSec = sysTimeSec;
    }
    
    @JsonIgnore
    public int getSysTimeNsec() {
        return sysTimeNsec;
    }
    @JsonProperty("sys_time_nsec")
    public void setSysTimeNsec(int sysTimeNsec) {
        this.sysTimeNsec = sysTimeNsec;
    }
    
    @JsonIgnore
    public long getSysUpTimeSec() {
        return sysUpTimeSec;
    }
    @JsonProperty("sys_uptime")
    public long getSysUpTimeMillis() {
        return sysUpTimeSec * 1000 + sysUpTimeMsec;
    }
    @JsonProperty("sys_uptime_sec")
    public void setSysUpTimeSec(long sysUpTimeSec) {
        this.sysUpTimeSec = sysUpTimeSec;
    }
    
    @JsonIgnore
    public long getSysUpTimeMsec() {
        return sysUpTimeMsec;
    }
    @JsonProperty("sys_uptime_msec")
    public void setSysUpTimeMsec(long sysUpTimeMsec) {
        this.sysUpTimeMsec = sysUpTimeMsec;
    }
    
    @JsonProperty("tag")
    public int getTag() {
        return tag;
    }
    @JsonProperty("tag")
    public void setTag(int tag) {
        this.tag = tag;
    }
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("LogMessage:\nreceiveTime: [");
        sb.append(timeMillis);
        sb.append("]\nconnection: [");
        sb.append(connection);
        sb.append("]\nagentIp: [");
        sb.append(agentIp);
        sb.append("]\nbytes: [");
        sb.append(bytes);
        sb.append("]\npackets: [");
        sb.append(packets);
        sb.append("]\ncrc32: [");
        sb.append(crc32);
        sb.append("]\ndstIfIndex: [");
        sb.append(dstIfIndex);
        sb.append("]\nsrcIfIndex: [");
        sb.append(srcIfIndex);
        sb.append("]\ndstIp: [");
        sb.append(dstIp);
        sb.append("]\nsrcIp: [");
        sb.append(srcIp);
        sb.append("]\ndirection: [");
        sb.append(direction);
        sb.append("]\ndstMac: [");
        sb.append(dstMac);
        sb.append("]\nsrcMac: [");
        sb.append(srcMac);
        sb.append("]\ndnsName: [");
        sb.append(dnsName);
        sb.append("]\ndstPort: [");
        sb.append(dstPort);
        sb.append("]\nsrcPort: [");
        sb.append(srcPort);
        sb.append("]\ndstAsn: [");
        sb.append(dstAsn);
        sb.append("]\nsrcAsn: [");
        sb.append(srcAsn);
        sb.append("]\ndstCidrMask: [");
        sb.append(dstCidrMask);
        sb.append("]\nsrcCidrMask: [");
        sb.append(srcCidrMask);
        sb.append("]\nengineId: [");
        sb.append(engineId);
        sb.append("]\nengineType: [");
        sb.append(engineType);
        sb.append("]\nethType: [");
        sb.append(ethType);
        sb.append("]\nflowMillis: [");
        sb.append(this.getFlowMillis());
        sb.append("]\nflowStart: [");
        sb.append(ISO8601Utils.format(this.getFlowStart()));
        sb.append("]\nflowStop: [");
        sb.append(ISO8601Utils.format(this.getFlowStop()));
        sb.append("]\ngatewayIp: [");
        sb.append(gatewayIp);
        sb.append("]\nicmpType: [");
        sb.append(icmpType);
        sb.append("]\nicmpCode: [");
        sb.append(icmpCode);
        sb.append("]\nipProtocol: [");
        sb.append(ipProtocol);
        sb.append("]\nipTos: [");
        sb.append(ipTos);
        sb.append("]\nipTtl: [");
        sb.append(ipTtl);
        sb.append("]\ntcpFlags: [");
        sb.append(tcpFlags);
        sb.append("]\niocType: [");
        sb.append(iocType);
        sb.append("]\niocValue: [");
        sb.append(iocValue);
        sb.append("]\niocDns: [");
        sb.append(iocDns);
        sb.append("]\niocFileId: [");
        sb.append(iocFileId);
        sb.append("]\niocId: [");
        sb.append(iocId);
        sb.append("]\niocIp: [");
        sb.append(iocIp);
        sb.append("]\niocThreatType: [");
        sb.append(iocThreatType);
        sb.append("]\nl4Length: [");
        sb.append(l4Length);
        sb.append("]\nlength: [");
        sb.append(length);
        sb.append("]\nmessage: [");
        sb.append(message);
        sb.append("]\nnetflowVersion: [");
        sb.append(netflowVersion);
        sb.append("]\nportId: [");
        sb.append(portId);
        sb.append("]\nisSelf: [");
        sb.append(isSelf);
        sb.append("]\nseqNum: [");
        sb.append(seqNum);
        sb.append("]\nsource: [");
        sb.append(source);
        sb.append("]\nsourceId: [");
        sb.append(sourceId);
        sb.append("]\nsysTime: [");
        sb.append(ISO8601Utils.format(this.getSysTime()));
        sb.append("]\nsysUpTimeMillis: [");
        sb.append(this.getSysUpTimeMillis());
        sb.append("]\ntag: [");
        sb.append(tag);
        sb.append("\n");
        return sb.toString();
    }
}
