package net.mhcomputing.sdn_sensor.threats;

import java.io.BufferedReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.mhcomputing.sdn_sensor.utils.DomainTable;

public class SpamhausReport implements ThreatReport<BufferedReader> {
    private static Logger log =
        LoggerFactory.getLogger(SpamhausReport.class);
    
    public SpamhausReport() {
        connections = new ArrayList<Connection>();
    }
    
    private static final Pattern spamhausPattern = Pattern.compile("(.*?) ; (.*)");
    
    private List<Connection> connections;
    
    @Override
    public void read(String context, long createdTime, BufferedReader reportRaw) {
        String line;
        int i = 0;
        try {
            connections.clear();
            while ((line = reportRaw.readLine()) != null) {
                i++;
                if (line.startsWith(";")) continue;
                Matcher m = spamhausPattern.matcher(line);
                if (m.lookingAt()) {
                    String cidr = m.group(1);
                    String comment = m.group(2);
                    Connection conn = Connection.getCidrConnection(createdTime, ConnectionType.CIDR_DST, cidr, comment, null);
                    conn.setReportType(ReportType.SPAMHAUS);
                    connections.add(conn);
                    log.trace("spamhaus context {}: parsed line {} connection:\n{}", context, line, conn);
                }
            }
        }
        catch (Exception e) {
            log.warn("could not parse spamhaus report at line {}", i);
        }
    }
    
    @Override
    public List<Connection> getConnections() {
        return connections;
    }

    @Override
    public DomainTable getDomains() {
        return DomainTable.EMPTY;
    }
    
    @Override
    public int size() {
        return connections.size();
    }
}
