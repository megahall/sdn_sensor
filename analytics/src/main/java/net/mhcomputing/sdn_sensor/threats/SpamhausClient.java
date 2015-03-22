package net.mhcomputing.sdn_sensor.threats;

import java.io.BufferedReader;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.mhcomputing.sdn_sensor.utils.Utils;

public class SpamhausClient implements ThreatReportClient {
    private static Logger log =
        LoggerFactory.getLogger(SpamhausClient.class);
    
    public SpamhausClient() {
    }

    @Override
    public List<? extends ThreatReport<?>> getReports(long createdTime) {
        if (ThreatReportClient.INTEGRATION_MODE != IntegrationMode.LOCAL) {
            throw new IllegalStateException("unsupported integration mode ");
        }
        
        BufferedReader dropFile = Utils.getResourceReader("drop.txt", SpamhausClient.class);
        BufferedReader extDropFile = Utils.getResourceReader("edrop.txt", SpamhausClient.class);
        
        SpamhausReport dropReport = new SpamhausReport();
        SpamhausReport extDropReport = new SpamhausReport();
        
        dropReport.read("drop.txt", createdTime, dropFile);
        extDropReport.read("edrop.txt", createdTime, extDropFile);
        
        return Arrays.asList(new SpamhausReport[] { dropReport, extDropReport });
    }
    
    public static void main(String[] args) {
        ThreatUtils.runClient(log, new SpamhausClient());
    }
}
