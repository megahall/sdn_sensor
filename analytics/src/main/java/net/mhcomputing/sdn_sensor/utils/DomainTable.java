package net.mhcomputing.sdn_sensor.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.mhcomputing.sdn_sensor.threats.Connection;
import net.mhcomputing.sdn_sensor.threats.ConnectionType;
import net.mhcomputing.sdn_sensor.threats.ThreatApiClient;
import net.mhcomputing.sdn_sensor.threats.ReportType;

public class DomainTable implements ThreatApiClient {
    private static Logger log =
        LoggerFactory.getLogger(DomainTable.class);
    
    public static boolean IGNORE_WHITELIST = false;
    public static DomainTable EMPTY = new DomainTable();
    
    private static DomainTable maliciousTable = new DomainTable();
    public static DomainTable getMaliciousTable() {
        return maliciousTable;
    }
    
    private static DomainTable alexaTable = new DomainTable();
    public static DomainTable getAlexaTable() {
        return alexaTable;
    }
    static {
        alexaTable.loadAlexa("src/main/resources/top-1m.csv");
    }
    
    public DomainTable() {
        domainHash = new HashMap<String, String>();
    }

    private HashMap<String, String> domainHash;
    
    private static ArrayList<String> getPartitions(String rdomain) {
        String[] rparts = rdomain.split("\\.", -1);
        ArrayList<String> partitions = new ArrayList<String>(rparts.length);
        
        for (int i = 0; i < rparts.length; ++i) {
            ArrayList<String> current = new ArrayList<String>(i + 1);
            for (int j = 0; j <= i; ++j) {
                current.add(rparts[j]);
            }
            String partition = org.apache.commons.lang3.StringUtils.join(current, '.');
            partitions.add(partition);
        }
        
        return partitions;
    }
    
    private static String reverseDomain(String domain) {
        String[]      rparts    = domain.split("\\.", -1);
        ArrayUtils.reverse(rparts);
        String        rdomain   = org.apache.commons.lang3.StringUtils.join(rparts, '.');
        return rdomain;
    }
    
    public void loadAlexa(String alexaFilePath) {
        String line = null;
        int    i    = 0;
        
        try {
            File topDomainsFile = new File(alexaFilePath);
            Reader topDomainsReader = new FileReader(topDomainsFile);
            BufferedReader topDomains = new BufferedReader(topDomainsReader);
            
            while ((line = topDomains.readLine()) != null) {
                i++;
                String[]      items     = line.split(",", 2);
                String        rank      = items[0];
                String        domain    = items[1].trim().replaceAll("/.*", "");
                String        rdomain   = reverseDomain(domain);
                domainHash.put(rdomain, domain);
                
                log.trace("domain table: parsed line {}: rank: {} domain: {} rdomain: {}", line, rank, domain, rdomain);
            }
            
            topDomains.close();
        }
        catch (Exception e) {
            String message = "could not parse top domain list at line " + i + ":\n" + line;
            log.warn(message);
            throw new RuntimeException(message, e);
        }
    }
    
    public boolean isPresent(String domain) {
        if (IGNORE_WHITELIST && this == alexaTable) {
            return false;
        }
        
        String  tdomain   = get(domain, true);
        boolean isPresent = (tdomain != null);
        
        log.debug("domain table: domain {} tdomain {} isPresent {}",
            domain, tdomain, isPresent);
        
        return isPresent;
    }
    
    public int size() {
        return domainHash.size();
    }

    public boolean isEmpty() {
        return domainHash.isEmpty();
    }

    public String get(String domain, boolean includePartitions) {
        String            rdomain    = reverseDomain(domain);
        ArrayList<String> partitions = getPartitions(rdomain);
        String            tdomain    = null;
        
        if (includePartitions) {
            for (String partition : partitions) {
                if ((tdomain = domainHash.get(partition)) != null) {
                    break;
                }
            }
        }
        else {
            tdomain = domainHash.get(domain);
        }
        
        log.debug("domain table: domain {} rdomain {} tdomain {}",
            domain, rdomain, tdomain);
        
        return tdomain;
    }
    
    public String get(Connection conn, boolean includePartitions) {
        if (IGNORE_WHITELIST && this == alexaTable) {
            return null;
        }
        
        if (conn.getType() == ConnectionType.DNS) {
            String  query        = conn.getDnsQuery();
            String  response     = conn.getDnsResponse();
            boolean isOkResponse = conn.getDnsType().isNameResponse();
            String  badQuery     = get(query, includePartitions);
            String  badResponse  = isOkResponse ? get(response, includePartitions) : null;
            return badQuery != null ? badQuery : badResponse;
        }
        else if (conn.getType() == ConnectionType.URL) {
            return get(conn.getUrlHost(), includePartitions);
        }
        else {
            return null;
        }
    }
    
    public void put(Connection conn, boolean includePartitions) {
        if (conn.getType() == ConnectionType.DNS) {
            String query         = conn.getDnsQuery();
            String response      = conn.getDnsResponse();
            boolean isOkResponse = conn.getDnsType().isNameResponse();
            put(query, includePartitions);
            if (isOkResponse)
                put(response, includePartitions);
        }
        else if (conn.getType() == ConnectionType.URL) {
            put(conn.getUrlHost(), includePartitions);
        }
        else {
            /* nothing */
        }
    }
    
    public void put(String line, boolean includePartitions) {
        String domain  = line.trim().replaceAll("/.*", "");
        String rdomain = reverseDomain(domain);
        
        log.debug("domain table: adding line {}: domain: {} rdomain: {} partitions: {}", line, domain, rdomain, includePartitions);
        
        domainHash.put(rdomain, domain);
        if (includePartitions) {
            ArrayList<String> partitions = getPartitions(rdomain);
            for (String partition: partitions) {
                domainHash.put(partition, domain);
            }
        }
    }
    
    public void putAll(DomainTable that) {
        this.domainHash.putAll(that.domainHash);
    }
    
    @Override
    public List<Connection> getMalicious(Connection conn) {
        if (IGNORE_WHITELIST && this == alexaTable) {
            /* do nothing */
        }
        else if (conn.getType() == ConnectionType.DNS) {
            String  query         = conn.getDnsQuery();
            String  response      = conn.getDnsResponse();
            boolean isOkResponse  = conn.getDnsType().isNameResponse();
            String  badQuery      = get(query, true);
            String  badResponse   = isOkResponse ? get(response, true) : null;
            boolean isBadQuery    = badQuery != null;
            boolean isBadResponse = badResponse != null;
            boolean isBadConn     = isBadQuery || isBadResponse;
            
            if (isBadConn) {
                Connection mconn = Connection.getDnsConnection(conn.getCreatedTime(), conn.getDnsType().toString(), conn.getDnsQuery(), conn.getDnsResponse());
                conn.setComment("DomainTable-DNS-" + badQuery != null ? badQuery : badResponse != null ? badResponse : "UNKNOWN");
                conn.setReportType(ReportType.DNS);
                return Arrays.asList(mconn);
            }
        }
        else if (conn.getType() == ConnectionType.URL) {
            String mdomain = get(conn.getUrlHost(), true);
            if (mdomain != null) {
                Connection mconn = Connection.getUrlConnection(conn.getCreatedTime(), conn.getDstIp(), conn.getDstPort(), conn.getIocId(), conn.getUrlHost(), conn.getUrlPath(), "GET", "");
                conn.setComment("DomainTable-URL-" + mdomain);
                conn.setReportType(ReportType.DNS);
                return Arrays.asList(mconn);
            }
        }
        
        // fall-through: return empty conn list
        return Collections.emptyList();
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getName());
        sb.append(": {\n");
        sb.append("connKeyHash: {\n");
        int i = 0;
        for (String domain : domainHash.values()) {
            sb.append("    entry [").append(i).append("] domain [").append(domain).append("]\n");
            ++i;
        }
        sb.append("}\n");
        sb.append("}");
        return sb.toString();
    }

    public static void main(String[] args) {
        org.apache.log4j.Logger rawlog = org.apache.log4j.Logger.getLogger(DomainTable.class);
        rawlog.setLevel(org.apache.log4j.Level.DEBUG);
        
        DomainTable domainTable = new DomainTable();
        domainTable.loadAlexa("src/main/resources/top-1m.csv");
        boolean ip1 = domainTable.isPresent("");
        boolean ip2 = domainTable.isPresent(".");
        boolean ip3 = domainTable.isPresent("www.google.co.in");
        boolean ip4 = domainTable.isPresent("ns1.google.com");
        log.warn("ip1 {} ip2 {} ip3 {} ip4 {}", ip1, ip2, ip3, ip4);
    }
}
