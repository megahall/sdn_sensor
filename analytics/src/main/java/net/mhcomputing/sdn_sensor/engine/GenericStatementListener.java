package net.mhcomputing.sdn_sensor.engine;

import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.espertech.esper.client.EPServiceProvider;
import com.espertech.esper.client.EPStatement;
import com.espertech.esper.client.EventBean;
import com.espertech.esper.client.StatementAwareUpdateListener;

import net.mhcomputing.sdn_sensor.threats.Connection;
import net.mhcomputing.sdn_sensor.threats.ConnectionTable;
import net.mhcomputing.sdn_sensor.threats.ReportType;
import net.mhcomputing.sdn_sensor.types.LogMessage;
import net.mhcomputing.sdn_sensor.utils.Utils;

public class GenericStatementListener implements StatementAwareUpdateListener {
    private static Logger log =
        LoggerFactory.getLogger(GenericStatementListener.class);
    
    private static ConnectionTable connTable = ConnectionTable.getInstance();
    
    private AtomicLong counter;
    
    public GenericStatementListener() {
        counter = new AtomicLong(0);
    }

    @Override
    public void update(EventBean[] newEvents, EventBean[] oldEvents, EPStatement statement, EPServiceProvider epSpi) {
        for (EventBean event : newEvents) {
            LogMessage lm = (LogMessage) event.getUnderlying();
            try {
                Connection conn = lm.getConnection();
                Connection mconn = connTable.getMalicious(conn);
                String hashKey = conn.getEscapedHashKey();
                
                if (mconn.getReportType() != null && mconn.getReportType() == ReportType.SPAMHAUS) {
                    log.warn("malicious CIDR match: Conn: {}\nMConn: {}", conn, mconn);
                }
                else if (counter.getAndIncrement() % 1_000 == 0) {
                    log.info("generic listener received LM seqNo {} hashKey {}", lm.getSeqNum(), hashKey);
                }
            }
            catch (Exception e) {
                log.warn("could not process log message\n{}LM:\n{}", Utils.displayStackTrace(e.getStackTrace()), lm);
                System.exit(1);
            }
        }
    }
}
