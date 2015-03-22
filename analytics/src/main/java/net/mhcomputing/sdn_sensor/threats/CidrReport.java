package net.mhcomputing.sdn_sensor.threats;

import java.io.BufferedReader;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.mhcomputing.sdn_sensor.utils.DomainTable;

public class CidrReport implements ThreatReport<BufferedReader> {
    private static Logger log =
        LoggerFactory.getLogger(CidrReport.class);
    
    public CidrReport(ConnectionType type) {
        this.type = type;
        this.connections = new ArrayList<Connection>();
    }
    
    private ConnectionType type;
    private List<Connection> connections;
    
    @Override
    public void read(String context, long createdTime, BufferedReader reportRaw) {
        String line;
        int i = 0;
        try {
            connections.clear();
            while ((line = reportRaw.readLine()) != null) {
                i++;
                if (line.startsWith(";") || line.startsWith("#")) continue;
                String cidr = line;
                String comment = context + "-line-" + Integer.toString(i);
                Connection conn = Connection.getCidrConnection(createdTime, type, cidr, comment, null);
                conn.setReportType(ReportType.CIDR);
                connections.add(conn);
                log.trace("cidr context {}: parsed line {}: connection:\n{}", context, line, conn);
            }
        }
        catch (Exception e) {
            log.warn("could not parse cidr report at line " + i, e);
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
