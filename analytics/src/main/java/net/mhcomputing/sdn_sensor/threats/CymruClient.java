package net.mhcomputing.sdn_sensor.threats;

import java.io.BufferedReader;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.mhcomputing.sdn_sensor.utils.Utils;

public class CymruClient implements ThreatReportClient {
    private static Logger log =
        LoggerFactory.getLogger(CymruClient.class);
    
    public CymruClient() {
    }

    @Override
    public List<? extends ThreatReport<?>> getReports(long createdTime) {
        if (ThreatReportClient.INTEGRATION_MODE != IntegrationMode.LOCAL) {
            throw new IllegalStateException("unsupported integration mode ");
        }
        
        BufferedReader cymruFile = Utils.getResourceReader("fullbogons-ipv4.txt", CymruClient.class);
        CidrReport cymruReport = new CidrReport(ConnectionType.CIDR_SRC);
        
        cymruReport.read("fullbogons-ipv4", createdTime, cymruFile);
        
        return Arrays.asList(new CidrReport[] { cymruReport });
    }
    
    public static void main(String[] args) {
        ThreatUtils.runClient(log, new CymruClient());
    }
}
