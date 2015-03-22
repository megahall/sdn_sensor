package net.mhcomputing.sdn_sensor.threats;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.mhcomputing.sdn_sensor.types.IocType;
import net.mhcomputing.sdn_sensor.types.LogMessage;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(include=JsonSerialize.Inclusion.NON_NULL)
public class Connection {
    private static Logger log =
        LoggerFactory.getLogger(Connection.class);
    
    public static final String EMPTY = "".intern();
    public static Connection EMPTY_CONNECTION = new Connection();
    
    // ASCII Unit Separator
    public static final String US = "\u001F";
    // ASCII Unit Separator Regex
    public static final String USR = "\\u001F";
    
    public static int IPPROTO_ICMP =  1;
    public static int IPPROTO_TCP  =  6;
    public static int IPPROTO_UDP  = 17;
    
    public static final String ipv4AddressRegex = "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))";
    public static final String ipv4CidrRegex = ipv4AddressRegex + "/(3[0-2]|[1-2]?[0-9])";
    private static final Pattern ipv4CidrPattern = Pattern.compile(ipv4CidrRegex);
    
    public Connection() {
        ipHashKey        = EMPTY;
        escapedIpHashKey = EMPTY;
        hashKey          = EMPTY;
        escapedHashKey   = EMPTY;
    }
    
    private ConnectionType type;
    private ReportType reportType;
    private long createdTime;
    private String comment;
    
    private String ipHashKey;
    private String escapedIpHashKey;
    private String hashKey;
    private String escapedHashKey;
    
    private String srcCidr;
    private String dstCidr;
    
    private String country;
    private String srcIp;
    private String dstIp;
    private int dstPort;
    
    private DnsType dnsType;
    private String dnsQuery;
    private String dnsResponse;
    
    private long iocId;
    private String urlHost;
    private String urlMethod;
    private String urlPath;
    private String userAgent;
    
    public ConnectionType getType() {
        return type;
    }
    public void setType(ConnectionType type) {
        this.type = type;
    }
    public void setType(String type) {
        this.type = ConnectionType.valueOf(type.toUpperCase());
    }
    
    public ReportType getReportType() {
        return reportType;
    }
    public void setReportType(ReportType reportType) {
        this.reportType = reportType;
    }
    public void setReportType(String reportType) {
        this.reportType = ReportType.valueOf(reportType.toUpperCase());
    }
    
    public long getCreatedTime() {
        return createdTime;
    }
    public void setCreatedTime(long createdTime) {
        this.createdTime = createdTime;
    }
    
    public String getComment() {
        return comment;
    }
    public void setComment(String comment) {
        this.comment = comment;
    }
    
    public String getSrcCidr() {
        return srcCidr;
    }
    public void setSrcCidr(String srcCidr) {
        this.srcCidr = srcCidr;
    }

    public String getDstCidr() {
        return dstCidr;
    }
    public void setDstCidr(String dstCidr) {
        this.dstCidr = dstCidr;
    }
    
    public String getCountry() {
        return country;
    }
    public void setCountry(String country) {
        this.country = country;
    }
    
    public String getSrcIp() {
        return srcIp;
    }
    public void setSrcIp(String srcIp) {
        this.srcIp = srcIp;
    }
    
    public String getDstIp() {
        return dstIp;
    }
    public void setDstIp(String dstIp) {
        this.dstIp = dstIp;
    }
    
    public int getDstPort() {
        return dstPort;
    }
    public void setDstPort(int dstPort) {
        this.dstPort = dstPort;
    }
    
    public DnsType getDnsType() {
        return dnsType;
    }
    public void setDnsType(DnsType dnsType) {
        this.dnsType = dnsType;
    }
    public void setDnsType(String dnsType) {
        this.dnsType = DnsType.valueOf(dnsType.toUpperCase());
    }
    
    public String getDnsQuery() {
        return dnsQuery;
    }
    public void setDnsQuery(String dnsQuery) {
        this.dnsQuery = dnsQuery;
    }
    
    public String getDnsResponse() {
        return dnsResponse;
    }
    public void setDnsResponse(String dnsResponse) {
        this.dnsResponse = dnsResponse;
    }
    
    public long getIocId() {
        return iocId;
    }
    public void setIocId(long iocId) {
        this.iocId = iocId;
    }
    
    public String getUrlHost() {
        return urlHost;
    }
    public void setUrlHost(String urlHost) {
        this.urlHost = urlHost;
    }
    
    public String getUrlMethod() {
        return urlMethod;
    }
    public void setUrlMethod(String urlMethod) {
        this.urlMethod = urlMethod;
    }
    
    public String getUrlPath() {
        return urlPath;
    }
    public void setUrlPath(String urlPath) {
        this.urlPath = urlPath;
    }
    
    public String getUserAgent() {
        return userAgent;
    }
    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getName());
        sb.append(": {\n    type: [");
        sb.append(type);
        sb.append("]\n    reportType: [");
        sb.append(reportType);
        sb.append("]\n    createdTime: [");
        sb.append(createdTime);
        sb.append("]\n    comment: [");
        sb.append(comment);
        sb.append("]\n    escapedIpHashKey: [");
        sb.append(escapedIpHashKey);
        sb.append("]\n    escapedHashKey: [");
        sb.append(escapedHashKey);
        sb.append("]\n    srcCidr: [");
        sb.append(srcCidr);
        sb.append("]\n    dstCidr: [");
        sb.append(dstCidr);
        sb.append("]\n    country: [");
        sb.append(country);
        sb.append("]\n    srcIp: [");
        sb.append(srcIp);
        sb.append("]\n    dstIp: [");
        sb.append(dstIp);
        sb.append("]\n    dstPort: [");
        sb.append(dstPort);
        sb.append("]\n    dnsType: [");
        sb.append(dnsType);
        sb.append("]\n    dnsQuery: [");
        sb.append(dnsQuery);
        sb.append("]\n    dnsResponse: [");
        sb.append(dnsResponse);
        sb.append("]\n    urlHost: [");
        sb.append(urlHost);
        sb.append("]\n    urlMethod: [");
        sb.append(urlMethod);
        sb.append("]\n    urlPath: [");
        sb.append(urlPath);
        sb.append("]\n    userAgent: [");
        sb.append(userAgent);
        sb.append("]\n}");
        return sb.toString();
    }
    
    public String getIpHashKey() {
        if (ipHashKey == EMPTY) ipHashKey = calculateHashKey(ConnectionType.IP);
        return ipHashKey;
    }
    
    @JsonIgnore
    public String getEscapedIpHashKey() {
        if (escapedIpHashKey == EMPTY) escapedIpHashKey = StringEscapeUtils.escapeJava(getIpHashKey());
        return escapedIpHashKey;
    }
    
    public String getHashKey() {
        if (hashKey == EMPTY) hashKey = calculateHashKey(getType());
        return hashKey;
    }
    
    @JsonIgnore
    public String getEscapedHashKey() {
        if (escapedHashKey == EMPTY) escapedHashKey = StringEscapeUtils.escapeJava(getHashKey());
        return escapedHashKey;
    }
    
    private String calculateHashKey(ConnectionType connType) {
        switch (connType) {
            case IP: case ICMP: {
                return connType.name() + US + srcIp + US + dstIp + US;
            }
            case CIDR_SRC: case CIDR_DST: {
                return EMPTY;
            }
            case TCP: case UDP: {
                // return connType.name() + US + srcIp + US + dstIp + US;
                return connType.name() + US + srcIp + US + dstIp + US + dstPort + US;
            }
            case DNS: {
                // XXX: is this correct?
                return connType.name() + US + dnsQuery + US + dnsType + US;
            }
            case URL: {
                // XXX: should the URL Path get included or not?
                // return type.name() + US + urlHost + US + urlPath + US;
                return connType.name() + US + urlHost + US;
            }
            default: {
                throw new IllegalArgumentException("unknown connection type " + connType);
            }
        }
    }
    
    public static Connection parseHashKey(String connStr) {
        String[] parts = connStr.split(USR, -1);
        
        Connection conn = new Connection();
        
        ConnectionType type = ConnectionType.valueOf(parts[0]);
        conn.setType(type);
        
        switch (type) {
            case IP: case ICMP: {
                conn.setSrcIp(parts[1]);
                conn.setDstIp(parts[2]);
                break;
            }
            case TCP: case UDP: {
                conn.setSrcIp(parts[1]);
                conn.setDstIp(parts[2]);
                break;
            }
            case DNS: {
                conn.setDnsQuery(parts[1]);
                conn.setDnsType(parts[2]);
                break;
            }
            case URL: {
                conn.setUrlHost(parts[1]);
                conn.setUrlPath(parts[2]);
                break;
            }
            default: {
                throw new IllegalArgumentException("unexpected connection type " + type);
            }
        }
        
        return conn;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (this.getClass() != o.getClass()) return false;
        
        Connection that = (Connection) o;
        
        if (this.type == null || that.type == null) /* nothing */;
        else if (this.type == null ^ that.type == null) return false;
        else if (this.type != that.type) return false;
        
        switch (this.getType()) {
            case CIDR_SRC: case CIDR_DST: {
                if (this.srcCidr == EMPTY && that.srcCidr == EMPTY) /* nothing */;
                else if (this.srcCidr == EMPTY ^ that.dstCidr == EMPTY) return false;
                else if (!this.srcCidr.equals(that.srcCidr)) return false;
                
                if (this.dstCidr == EMPTY && that.dstCidr == EMPTY) /* nothing */;
                else if (this.dstCidr == EMPTY ^ that.dstCidr == EMPTY) return false;
                else if (!this.dstCidr.equals(that.dstCidr)) return false;
            }
            case IP: case ICMP: case TCP: case UDP: {
                if (this.srcIp == null && that.srcIp == null) /* nothing */;
                else if (this.srcIp == null ^ that.srcIp == null) return false;
                else if (!this.srcIp.equals(that.srcIp)) return false;
                
                if (this.dstIp == null && that.dstIp == null) /* nothing */;
                else if (this.dstIp == null ^ that.dstIp == null) return false;
                else if (!this.dstIp.equals(that.dstIp)) return false;
            }
            case DNS: {
                if (this.dnsQuery == null && that.dnsQuery == null) /* nothing */;
                else if (this.dnsQuery == null ^ that.dnsQuery == null) return false;
                else if (!this.dnsQuery.equals(that.dnsQuery)) return false;
                
                // XXX: is this correct?
                if (this.dnsType == null && that.dnsType == null) /* nothing */;
                else if (this.dnsType == null ^ that.dnsType == null) return false;
                else if (!this.dnsType.equals(that.dnsType)) return false;
            }
            case URL: {
                if (this.urlHost == null && that.urlHost == null) /* nothing */;
                else if (this.urlHost == null ^ that.urlHost == null) return false;
                else if (!this.urlHost.equals(that.urlHost)) return false;
                
                if (this.urlPath == null && that.urlPath == null) /* nothing */;
                else if (this.urlPath == null ^ that.urlPath == null) return false;
                else if (!this.urlPath.equals(that.urlPath)) return false;
            }
        }
        
        return true;
    }
    
    // XXX: this probably won't work on broken objects with nulls in the wrong places
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        
        switch (this.getType()) {
            case IP: case ICMP: case TCP: case UDP: {
                result = prime * result + ((srcIp == null)    ? 0 : srcIp.hashCode());
                result = prime * result + ((dstIp == null)    ? 0 : dstIp.hashCode());
                break;
            }
            case CIDR_SRC: case CIDR_DST: {
                result = prime * result + ((srcCidr == null)  ? 0 : srcCidr.hashCode());
                result = prime * result + ((dstCidr == null)  ? 0 : dstCidr.hashCode());
                break;
            }
            case DNS: {
                result = prime * result + ((dnsQuery == null) ? 0 : dnsQuery.hashCode());
                result = prime * result + ((dnsType == null)  ? 0 : dnsType.hashCode());
                break;
            }
            case URL: {
                result = prime * result + ((urlHost == null)  ? 0 : urlHost.hashCode());
                result = prime * result + ((urlPath == null)  ? 0 : urlPath.hashCode());
                break;
            }
        }
        
        return result;
    }
    
    public static List<Connection> getAllValidConns(List<Connection> args) {
        List<Connection> allValidConns = new ArrayList<Connection>(args.size());
        
        for (Connection conn: args) {
            if (conn != null && conn != EMPTY_CONNECTION) allValidConns.add(conn);
        }
        return allValidConns;
    }
    public static String calculateCidr(String address, int mask) {
        try {
            InetAddress addr     = InetAddress.getByName(address);
            byte[]      bytes    = addr.getAddress();
            int         iAddress = ((bytes[0] & 0xff) << 24) | ((bytes[1] & 0xff) << 16) | ((bytes[2] & 0xff) << 8) | ((bytes[3] & 0xff) << 0);
            String      bAddress = Integer.toBinaryString(iAddress);
            String      pAddress = StringUtils.leftPad(bAddress, 32, '0');
            String      cidr     = pAddress.substring(0, mask);
            
            // log.info("address {} binary {} cidr {}", address, pAddress, cidr);
            
            return   cidr;
        }
        catch (Exception e) {
            log.warn("exception calculating binary string cidr", e);
            throw new RuntimeException(e);
        }
    }
    
    /*
     * Factory Methods
     * 
     * Cannot be constructors, because some of them have conflicting argument
     * lists. As factory methods they can have separate names to keep them
     * apart.
     * 
     */
    public static Connection getCidrConnection(long createdTime, ConnectionType type, String rawCidr, String comment, String country) {
        log.trace("create CIDR connection: {}", rawCidr);
        
        Matcher ipv4CidrMatcher = ipv4CidrPattern.matcher(rawCidr);
        // Look for a CIDR block address <ADDRESS> <SLASH> <SCOPE>.
        if (!ipv4CidrMatcher.find()) throw new IllegalArgumentException("invalid CIDR " + rawCidr);
        
        // Divide CIDR block into <ADDRESS> <SLASH> <SCOPE>.
        String sAddress = ipv4CidrMatcher.group(1);
        
        String sMask    = ipv4CidrMatcher.group(2);
        int    iMask    = Integer.parseInt(sMask);
        String cidr     = calculateCidr(sAddress, iMask);
        
        Connection c = new Connection();
        c.setType(type);
        c.setCreatedTime(createdTime);
        c.setComment(comment);
        if (type == ConnectionType.CIDR_SRC) {
            c.setSrcCidr(cidr);
            c.setSrcIp(rawCidr);
        }
        else if (type == ConnectionType.CIDR_DST) {
            c.setDstCidr(cidr);
            c.setDstIp(rawCidr);
        }
        else {
            throw new IllegalArgumentException("unexpected connection type " + type);
        }
        c.setCountry(country);
        
        return c;
    }
    
    public static Connection getIpConnection(long createdTime, String srcIp, String dstIp, int dstPort, ConnectionType type) {
        log.trace("create IP connection: {}:{}/{}", dstIp, dstPort, type);
        Connection c = new Connection();
        c.setType(type);
        c.setCreatedTime(createdTime);
        c.setSrcIp(srcIp);
        c.setDstIp(dstIp);
        c.setSrcCidr(calculateCidr(srcIp, 32));
        c.setDstCidr(calculateCidr(dstIp, 32));
        c.setDstPort(dstPort);
        return c;
    }
    
    public static Connection getIpConnection(long createdTime, String srcIp, String dstIp, int dstPort, ConnectionType type, String country) {
        log.trace("create IP connection: {}:{}/{}@{}", dstIp, dstPort, type, country);
        Connection c = new Connection();
        c.setType(type);
        c.setCreatedTime(createdTime);
        c.setCountry(country);
        c.setSrcIp(srcIp);
        c.setDstIp(dstIp);
        c.setSrcCidr(calculateCidr(srcIp, 32));
        c.setDstCidr(calculateCidr(dstIp, 32));
        c.setDstPort(dstPort);
        return c;
    }
    
    public static Connection getIpConnection(long createdTime, String srcIp, String dstIp, String dstPortStr, ConnectionType type) {
        return getIpConnection(createdTime, srcIp, dstIp, Integer.parseInt(dstPortStr), type);
    }
    
    public static Connection getIpConnection(long createdTime, String srcIp, String dstIp, String dstPortStr, ConnectionType type, String country) {
        return getIpConnection(createdTime, srcIp, dstIp, Integer.parseInt(dstPortStr), type, country);
    }
    
    public static Connection getDnsConnection(long createdTime, String dnsType, String dnsQuery, String dnsResponse) {
        log.debug("create DNS connection: Q {} R {} T {}", dnsQuery, dnsResponse, dnsType);
        Connection c = new Connection();
        c.setType(ConnectionType.DNS);
        c.setCreatedTime(createdTime);
        c.setDnsType(dnsType);
        c.setDnsQuery(dnsQuery.toLowerCase());
        c.setDnsResponse(dnsResponse.toLowerCase());
        return c;
    }
    
    public static Connection getUrlConnection(long createdTime, String urlHost, String urlPath, String urlMethod, String userAgent) {
        log.debug("create URL partial connection: {} http:// {} {}", urlMethod, urlHost, urlPath);
        Connection c = new Connection();
        c.setType(ConnectionType.URL);
        c.setCreatedTime(createdTime);
        c.setUrlHost(urlHost.toLowerCase());
        c.setUrlPath(urlPath);
        c.setUrlMethod(urlMethod);
        c.setUserAgent(userAgent);
        return c;
    }
    
    public static Connection getUrlConnection(long createdTime,
        String dstIp, int dstPort, long iocId,
        String urlHost, String urlPath, String urlMethod, String userAgent) {
        log.debug("create URL full connection: {} http:// {} {}", urlMethod, urlHost, urlPath);
        Connection c = new Connection();
        c.setType(ConnectionType.URL);
        c.setCreatedTime(createdTime);
        
        c.setDstIp(dstIp);
        c.setDstPort(dstPort);
        c.setIocId(iocId);
        c.setUrlHost(urlHost.toLowerCase());
        c.setUrlPath(urlPath);
        c.setUrlMethod(urlMethod);
        c.setUserAgent(userAgent);
        
        return c;
    }
    
    public static Connection getLogConnection(LogMessage lm) {
        return getLogConnection(lm.getTimeMillis(), lm);
    }
    
    public static Connection getLogConnection(long createdTime, LogMessage lm) {
        // XXX: add support for DNS Query logs if they exist
        if (lm.getIocType() == IocType.URL) {
            String[] urlParts = lm.getIocValue().split("/", 2);
            // XXX: fix hardcoded GET method on URLs if possible
            Connection conn = Connection.getUrlConnection(createdTime, lm.getDstIp(), lm.getDstPort(), lm.getIocId(), urlParts[0], "/" + urlParts[1], "GET", "");
            return conn;
        }
        else {
            // XXX: is support for IP but non (TCP,UDP) conns needed?
            ConnectionType type;
            if      (lm.getIpProtocol() == IPPROTO_ICMP) type = ConnectionType.ICMP;
            else if (lm.getIpProtocol() == IPPROTO_TCP)  type = ConnectionType.TCP;
            else if (lm.getIpProtocol() == IPPROTO_UDP)  type = ConnectionType.UDP;
            else                                         return null;
            
            //String srcIp, String dstIp, int dstPort, ConnectionType type, String country) {
            //String srcIp, String dstIp, String dstPortStr, ConnectionType type, String country)
            Connection conn = getIpConnection(createdTime, lm.getSrcIp(), lm.getDstIp(), lm.getDstPort(), type);
            return conn;
        }
    }    
}
