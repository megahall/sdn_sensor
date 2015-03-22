package net.mhcomputing.sdn_sensor.engine;

import java.net.PortUnreachableException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import net.mhcomputing.sdn_sensor.threats.Connection;
import net.mhcomputing.sdn_sensor.threats.ConnectionTable;
import net.mhcomputing.sdn_sensor.types.LogMessage;
import net.mhcomputing.sdn_sensor.utils.ByteBufferOutputStream;
import net.mhcomputing.sdn_sensor.utils.ChannelAction;
import net.mhcomputing.sdn_sensor.utils.ChannelFactory;
import net.mhcomputing.sdn_sensor.utils.ChannelType;
import net.mhcomputing.sdn_sensor.utils.JsonUtils;
import net.mhcomputing.sdn_sensor.utils.NanomsgLibrary;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.espertech.esper.client.EPServiceProvider;
import com.espertech.esper.client.EPStatement;
import com.espertech.esper.client.EventBean;
import com.espertech.esper.client.StatementAwareUpdateListener;
import com.espertech.esper.event.bean.BeanEventBean;
import com.espertech.esper.event.map.MapEventBean;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.common.base.CharMatcher;
import com.google.common.base.Splitter;

@Path("/")
public class AnalyticsStatementListener implements StatementAwareUpdateListener {
    private static final int QUEUE_LIMIT = 100_000;
    
    private static Logger log =
        LoggerFactory.getLogger(AnalyticsStatementListener.class);
    
    @SuppressWarnings("unused")
    private static final Splitter recordSplitter =
        Splitter.on(CharMatcher.is(',')).trimResults().omitEmptyStrings();

    private static final ReportMode reportMode = ReportMode.NANOMSG;
    private static NanomsgLibrary nml = NanomsgLibrary.getInstance();
    
    private static AtomicLong counter = new AtomicLong(0);
    private static ConnectionTable connTable = ConnectionTable.getInstance();
    private static ByteChannel channel;
    
    private static ConcurrentMap<String, Object> reportCache = new ConcurrentHashMap<String, Object>();
    private static volatile BlockingQueue<Object> reportQueue = new ArrayBlockingQueue<Object>(QUEUE_LIMIT);
    
    static {
        channel = ChannelFactory.getChannel(URI.create("udp://127.0.0.1:31338/"), ChannelAction.CONNECT);
    }
    
    private static ThreadLocal<Integer> nmSockets =
        new ThreadLocal<Integer>() {
            protected Integer initialValue() {
                int nmSocket = -1;
                if (reportMode == ReportMode.NANOMSG) {
                    nmSocket = nml.getSocket(nml.NN_PUSH);
                    nml.connectSocket(nmSocket, "tcp://127.0.0.1:31338");
                }
                return nmSocket;
            }
    };
    
    private static ThreadLocal<ByteBufferOutputStream> outputBuffers =
        new ThreadLocal<ByteBufferOutputStream>() {
            protected ByteBufferOutputStream initialValue() {
                ByteBuffer buffer = ByteBuffer.allocateDirect(65536);
                ByteBufferOutputStream stream = new ByteBufferOutputStream(buffer);
                return stream;
            }
    };
    
    private static ThreadLocal<ByteBuffer> sizeBuffers =
        new ThreadLocal<ByteBuffer>() {
            protected ByteBuffer initialValue() {
                ByteBuffer buffer = ByteBuffer.allocate(16);
                return buffer;
            }
    };
    
    public AnalyticsStatementListener() {
    }
        
    @Override
    public void update(EventBean[] newEvents, EventBean[] oldEvents, EPStatement statement, EPServiceProvider epSpi) {
        String statementName = statement.getName();
        String contextName   = AnalyticsServer.getStatementModel(statementName).getContextName();
        boolean isTopReport  = contextName != null && contextName.equals("TopContext");
        
        try {
            //long millis = epSpi.getEPRuntime().getCurrentTime();
            Date time = new Date(epSpi.getEPRuntime().getCurrentTime());
            
            if (newEvents != null && newEvents.length > 0) {
                Map<String, Object> event = null;
                ArrayList<Object> entries = null;
                
                if (isTopReport) {
                    event = new LinkedHashMap<String, Object>();
                    entries = new ArrayList<Object>(newEvents == null ? 0 : newEvents.length);
                }
                
                next_event: for (int i = 0; i < newEvents.length; ++i) {
                    Object newEvent = newEvents[i];
                    
                    if (!isTopReport) {
                        event = new LinkedHashMap<String, Object>();
                        entries = new ArrayList<Object>(newEvents == null ? 0 : newEvents.length);
                    }
                    event.put("statement", statementName);
                    event.put("time", time);
                    
                    if (newEvent != null) {
                        if (newEvent instanceof MapEventBean) {
                            this.handleMapEvent(statementName, isTopReport, (MapEventBean) newEvent, entries);
                        }
                        else if (newEvent instanceof BeanEventBean) {
                            this.handleBeanEvent(statementName, isTopReport, (BeanEventBean) newEvent, entries);
                        }
                        else {
                            log.warn("unknown event type {}", newEvent.getClass().getName());
                            continue next_event;
                        }
                        
                        if (!isTopReport)
                            writeEvent(statementName, isTopReport, event, entries);
                    }
                    else {
                        log.warn("null event received");
                        continue next_event;
                    }
                }
                if (isTopReport)
                    writeEvent(statementName, isTopReport, event, entries);
            }
        }
        catch (Exception e) {
            log.warn("could not produce JSON report type " + statementName, e);
        }
    }
    
    public void handleBeanEvent(String statementName, boolean isTopReport, EventBean newEvent, ArrayList<Object> entries) {
        LogMessage lm    = (LogMessage) newEvent.getUnderlying();
        Map<String, Object> properties = new LinkedHashMap<String, Object>();
        // XXX: clean up this logic a bit
        boolean isUseful = false;
        properties.put("lm", lm);
        
        Connection conn  = lm.getConnection();
        if (conn != null) {
            Connection mconn = connTable.getMalicious(conn);
            if (mconn != null) {
                properties.put("conn",  conn);
                properties.put("mconn", mconn);
                isUseful = true;
            }
            else {
                isUseful = true;
            }
        }
        
        if (isUseful) entries.add(properties);
    }
    
    public void handleMapEvent(String statementName, boolean isTopReport, MapEventBean mapEvent, ArrayList<Object> entries) {
        Map<String, Object> rawProperties = mapEvent.getProperties();
        Map<String, Object> properties = new LinkedHashMap<String, Object>();
        Set<Entry<String, Object>> entrySet = rawProperties.entrySet();
        for (Entry<String, Object> entry : entrySet) {
            String key   = entry.getKey();
            Object value = entry.getValue();
            
            if (value instanceof BeanEventBean) {
                BeanEventBean bean = (BeanEventBean) value;
                Object beanValue = bean.getUnderlying();
                properties.put(key, beanValue);
            }
            else if (value instanceof EventBean[]) {
                EventBean[] beans = (EventBean[]) value;
                Object[] beanValues = new Object[beans.length];
                for (int j = 0; j < beans.length; ++j) {
                    Object beanValue = beans[j].getUnderlying();
                    //if (LogMessage.class.isAssignableFrom(beanValue.getClass())) {
                    //    beanValues[j] = TypeUtils.filterLm((LogMessage) beanValue);
                    //}
                    //else {
                    //    beanValues[j] = beanValue;
                    //}
                    beanValues[j] = beanValue;
                }
                properties.put(key, beanValues);
            }
            else if (value instanceof LogMessage[]) {
                LogMessage[] lms = (LogMessage[]) value;
                //Object[] beanValues = new Object[lms.length];
                //for (int j = 0; j < lms.length; ++j) {
                //    LogMessage lm = lms[j];
                //    beanValues[j] = TypeUtils.filterLm(lm);
                //}
                properties.put(key, lms);
            }
            else if (value != null && LogMessage.class.isAssignableFrom(value.getClass())) {
                //properties.put(key, TypeUtils.filterLm((LogMessage) value));
                properties.put(key, (LogMessage) value);
            }
            else {
                properties.put(key, value);
            }
        }
        
        entries.add(properties);
    }
    
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String getRootResource() {
        return "SDN Sensor Analytics Service\n";
    }
    
    @GET
    @Path("/api/top_reports")
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> getTopReports() {
        // The ConcurrentHashMap iterator provides a self-consistent view of the Map.
        // Just copy the Concurrent Map to a non-concurrent Map to return snapshot.
        return new LinkedHashMap<String, Object>(reportCache);
    }
    
    @GET
    @Path("/api/queued_reports")
    @Produces(MediaType.APPLICATION_JSON)
    public List<Object> getQueuedReports() {
        ArrayList<Object> queuedReports = new ArrayList<Object>(QUEUE_LIMIT);
        reportQueue.drainTo(queuedReports);
        return queuedReports;
    }
        
    public void writeEvent(String statementName, boolean isTopReport, Map<String, Object> event, ArrayList<Object> entries) {
        // skip over uninteresting events
        if (entries.size() <= 0) return;
        
        String payload = null;
        
        try {
            event.put("size", entries.size());
            event.put("entries", entries);
            long eventId = counter.getAndIncrement();
            event.put("id", eventId);
            
            ObjectWriter writer = JsonUtils.getObjectWriter();
            
            if (log.isTraceEnabled() && !statementName.equals("MatchCorrelation")) {
                try {
                    payload = writer.writeValueAsString(event);
                    log.trace("JSON payload:\n{}", payload);
                }
                catch (Exception e) {
                    /* XXX: do nothing for now */
                }
            }
            
            if (reportMode.isRealtime()) {
                ByteBufferOutputStream stream = outputBuffers.get();
                ByteBuffer buffer = stream.getBuffer();
                
                buffer.clear();
                try {
                    writer.writeValue(stream, event);
                }
                catch (Exception e) {
                    if (payload == null) {
                        payload = writer.writeValueAsString(event).substring(0, 1024);
                    }
                }
                // insert UNIX newline for readability
                buffer.put((byte) 0x0A);
                buffer.flip();
                
                if (reportMode == ReportMode.NANOMSG) {
                    nml.sendMessage(nmSockets.get(), buffer, nml.NN_DONTWAIT);
                }
                else if (reportMode == ReportMode.SOCKET) {
                    ChannelType type = ChannelFactory.getChannelType(channel);
                    
                    // synchronized so length and value cannot be interleaved
                    // prevents corrupting the output stream
                    try {
                        synchronized (channel) {
                            if (type == ChannelType.TCP) {
                                ByteBuffer sizeBuffer = sizeBuffers.get();
                                sizeBuffer.clear();
                                sizeBuffer.putInt(buffer.limit() - buffer.position());
                                sizeBuffer.flip();
                                channel.write(sizeBuffer);
                            }
                            
                            channel.write(buffer);
                        }
                    }
                    catch (PortUnreachableException pue) {
                        /* XXX: do nothing for now */
                    }
                }
                
                if (!statementName.equals("MatchCorrelation")) {
                    log.debug("wrote JSON report type {} size {}", statementName, buffer.limit());
                }
            }
            else {
                if (isTopReport) {
                    reportCache.put(statementName, event);
                }
                else {
                    boolean isOk = reportQueue.offer(event);
                    if (!isOk && (long) eventId % 100 == 0) {
                        log.warn("event id {} could not be queued", eventId);
                    }
                }
            }            
        }
        catch (Exception e) {
            log.warn("could not write JSON report type {}: {}: payload:\n{}", statementName, e.toString(), payload);
        }
    }
}
