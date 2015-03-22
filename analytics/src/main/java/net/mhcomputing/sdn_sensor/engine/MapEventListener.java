package net.mhcomputing.sdn_sensor.engine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.espertech.esper.client.EPServiceProvider;
import com.espertech.esper.client.EPStatement;
import com.espertech.esper.client.EventBean;
import com.espertech.esper.client.StatementAwareUpdateListener;
import com.espertech.esper.event.map.MapEventBean;

import net.mhcomputing.sdn_sensor.utils.Utils;

public class MapEventListener implements StatementAwareUpdateListener {
    private static Logger log =
        LoggerFactory.getLogger(MapEventListener.class);
    
    public MapEventListener() {
    }
    
    @Override
    public void update(EventBean[] newEvents, EventBean[] oldEvents, EPStatement statement, EPServiceProvider epSpi) {
        StringBuilder sb = new StringBuilder();
        
        long millis = epSpi.getEPRuntime().getCurrentTime();
        String statementName = statement.getName();
        
        sb.append(statementName).append(" Entries at [").append(Utils.formatMillis(millis)).append("]:\n");
        
        if (newEvents == null || newEvents.length == 0) {
            sb.append("No Entries [").append(newEvents).append("]\n");
        }
        else {
            for (int i = 0; i < newEvents.length; ++i) {
                MapEventBean mapEvent = (MapEventBean) newEvents[i];
                sb.append("Entry ID [").append(i + 1).append("]:\n");
                sb.append(Utils.displayMapEvent(mapEvent));
            }
        }
        
        log.info(sb.toString());
    }
    
}
