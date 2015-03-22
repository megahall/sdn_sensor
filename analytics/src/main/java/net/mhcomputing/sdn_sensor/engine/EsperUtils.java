package net.mhcomputing.sdn_sensor.engine;

import java.util.Collections;
import java.util.List;

import net.mhcomputing.sdn_sensor.threats.Connection;
import net.mhcomputing.sdn_sensor.threats.ConnectionTable;
import net.mhcomputing.sdn_sensor.threats.GoogleThreatApiClient;
import net.mhcomputing.sdn_sensor.threats.ThreatApiClient;
import net.mhcomputing.sdn_sensor.types.LogMessage;
import net.mhcomputing.sdn_sensor.utils.DomainTable;

/*
 * WARNING: These functions are registered with the event engine.
 * 
 * Do not change behavior, move, or rename them without updating the engine
 * configuration and event rules to match.
 */
public class EsperUtils {
    private static ConnectionTable  connTable      = ConnectionTable.getInstance();
    private static DomainTable      alexaTable     = DomainTable.getAlexaTable();
    private static DomainTable      maliciousTable = DomainTable.getMaliciousTable();
    @SuppressWarnings("unused")
    private static ThreatApiClient gsbClient      = new GoogleThreatApiClient(true); 
    
    public static boolean isMalicious(Connection conn) {
        // null means a log message which does not represent a network connection
        if (conn == null) return false;
        
        return getMalicious(conn) != null;
    }
    
    public static Connection getMalicious(Connection conn) {
        Connection       mconn      = connTable.getMalicious(conn);
        String           wldomain   = alexaTable.get(conn, true);
        @SuppressWarnings("unchecked")
        List<Connection> dconns     = (List<Connection>) (wldomain != null ? Collections.emptyList() : maliciousTable.getMalicious(conn));
        // List<Connection> gconns     = gsbClient.getMalicious(conn); 
        List<Connection> gconns     = Collections.emptyList();
        
        Connection       fmconn     = mconn != null ? mconn : !dconns.isEmpty() ? dconns.get(0) : !gconns.isEmpty() ? gconns.get(0) : null;
        return fmconn;
    }
    
    public static int hashLm(LogMessage lm) {
        return (int) lm.getHashKey().hashCode();
    }
    
    public static String toLowerCase(String s) {
        return s.toLowerCase();
    }
    
    public static String toUpperCase(String s) {
        return s.toUpperCase();
    }
}
