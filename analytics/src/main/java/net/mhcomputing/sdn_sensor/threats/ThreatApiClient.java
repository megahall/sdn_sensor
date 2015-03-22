package net.mhcomputing.sdn_sensor.threats;

import java.util.List;

public interface ThreatApiClient {
    public static final IntegrationMode INTEGRATION_MODE = IntegrationMode.LOCAL;
    
    public List<Connection> getMalicious(Connection conn);
}