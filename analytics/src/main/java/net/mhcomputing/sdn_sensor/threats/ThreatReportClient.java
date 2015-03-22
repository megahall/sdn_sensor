package net.mhcomputing.sdn_sensor.threats;

import java.util.List;

public interface ThreatReportClient {
    public static final IntegrationMode INTEGRATION_MODE = IntegrationMode.LOCAL;
    
    public List<? extends ThreatReport<?>> getReports(long createdTime);
}