package net.mhcomputing.sdn_sensor.engine;

import net.mhcomputing.sdn_sensor.threats.Connection;
import net.mhcomputing.sdn_sensor.types.LogMessage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.espertech.esper.client.EPRuntime;

public class LogMessageHolder implements Runnable {
    private static Logger log =
        LoggerFactory.getLogger(LogMessageHolder.class);
    
    /*
     * The esperService is used to submit the log message events into Esper.
     */
    private static EPRuntime esperService;
    public static EPRuntime getEsperService() {
        return esperService;
    }
    public static void setEsperService(EPRuntime esperService) {
        LogMessageHolder.esperService = esperService;
    }
    
    public LogMessageHolder() {
    }
    
    public LogMessageHolder(LogMessage lm) {
        this.lm = lm;
    }
    
    private LogMessage lm;

    public LogMessage getLm() {
        return lm;
    }

    public void setLm(LogMessage lm) {
        this.lm = lm;
    }
    
    public void run() {
        Connection conn;
        
        try {
            conn = Connection.getLogConnection(lm);
            lm.setConnection(conn);
            lm.getConnection().getHashKey();
            esperService.sendEvent(lm);
        }
        catch (Exception e) {
            String type = (lm == null ? "UNKNOWN" : lm.getSource().toString());
            long seqno = (lm == null ? 0 : lm.getSeqNum());
            log.error("error processing queued message ID [" + type + "-" + seqno + "]", e);
        }
    }
    
    public String toString() {
        return lm.toString();
    }
}
