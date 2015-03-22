package net.mhcomputing.sdn_sensor.threats;

import java.util.List;

import org.slf4j.Logger;

import net.mhcomputing.sdn_sensor.utils.DomainTable;

public class ThreatUtils {
    public static void runClient(Logger log, ThreatReportClient client) {
        org.apache.log4j.Logger rawlog;
        rawlog = org.apache.log4j.Logger.getLogger(client.getClass());
        rawlog.setLevel(org.apache.log4j.Level.DEBUG);
        rawlog = org.apache.log4j.Logger.getLogger(DomainTable.class);
        rawlog.setLevel(org.apache.log4j.Level.DEBUG);
        
        List<? extends ThreatReport<?>> reports = client.getReports(System.currentTimeMillis());
        ThreatReport<?> example = reports.get(0);
        List<Connection> connList = example.getConnections();
        int i = 0;
        for (Connection conn : connList) {
            log.info("conn {}:\n{}", i, conn);
            ++i;
        }
    }
    
    public static int getTotalSize(ThreatReport<?>... reports) {
        int size = 0;
        
        for (ThreatReport<?> report : reports) {
            size += report.size();
        }
        
        return size;
    }
}
