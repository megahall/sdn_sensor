package net.mhcomputing.sdn_sensor.engine;

import java.io.File;
import java.net.URI;
import java.util.Collections;
import java.util.Formatter;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.mhcomputing.sdn_sensor.threats.Connection;
import net.mhcomputing.sdn_sensor.threats.ConnectionTable;
import net.mhcomputing.sdn_sensor.threats.CymruClient;
import net.mhcomputing.sdn_sensor.threats.SpamhausClient;
import net.mhcomputing.sdn_sensor.threats.ThreatReport;
import net.mhcomputing.sdn_sensor.types.LogMessage;
import net.mhcomputing.sdn_sensor.utils.ChannelAction;
import net.mhcomputing.sdn_sensor.utils.CustomJacksonFeature;
import net.mhcomputing.sdn_sensor.utils.DomainTable;
import net.mhcomputing.sdn_sensor.utils.Utils;

import org.glassfish.grizzly.http.CompressionConfig;
import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.grizzly.http.server.NetworkListener;
import org.glassfish.grizzly.http.server.ServerConfiguration;
import org.glassfish.grizzly.http.server.accesslog.AccessLogAppender;
import org.glassfish.grizzly.http.server.accesslog.AccessLogFormat;
import org.glassfish.grizzly.http.server.accesslog.AccessLogProbe;
import org.glassfish.grizzly.http.server.accesslog.ApacheLogFormat;
import org.glassfish.grizzly.http.server.accesslog.StreamAppender;
import org.glassfish.jersey.filter.LoggingFilter;
import org.glassfish.jersey.grizzly2.httpserver.GrizzlyHttpServerFactory;
import org.glassfish.jersey.message.DeflateEncoder;
import org.glassfish.jersey.message.GZipEncoder;
import org.glassfish.jersey.server.ResourceConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.espertech.esper.client.Configuration;
import com.espertech.esper.client.EPAdministrator;
import com.espertech.esper.client.EPRuntime;
import com.espertech.esper.client.EPServiceProvider;
import com.espertech.esper.client.EPServiceProviderManager;
import com.espertech.esper.client.EPStatement;
import com.espertech.esper.client.StatementAwareUpdateListener;
import com.espertech.esper.client.soda.EPStatementObjectModel;
import com.espertech.esper.client.time.CurrentTimeEvent;
import com.espertech.esper.core.service.EPServiceProviderImpl;

public class AnalyticsServer implements Runnable {
    private static final Logger log =
        LoggerFactory.getLogger(AnalyticsServer.class);
    
    private static final String ESPER_URI = "AnalyticsServer";
    //private static final ThreadMode THREAD_MODE = ThreadMode.EXECUTOR;
    private static final ThreadMode THREAD_MODE = ThreadMode.ESPER;
    private static final int THREAD_COUNT = 16;
    private static final long TICK_SIZE = 100;
    
    private static boolean REPLAY_MODE = false;
    
    private HttpServer httpServer;
    
    private ThreadFactory threadFactory;
    private EngineRejectionHandler rejectionHandler;
    private BlockingQueue<Runnable> executorQueue;
    private ThreadPoolExecutor executor;
    
    private Configuration config;
    
    private EPServiceProvider esperSpi;
    private EPServiceProviderImpl esperSpiImpl;
    private EPRuntime esperService;
    private EPAdministrator esperAdmin;
    
    private List<String> statements;
    private static HashMap<String, EPStatementObjectModel> statementModels;
    public static EPStatementObjectModel getStatementModel(String statementName) {
        return statementModels.get(statementName);
    }
    
    private LogMessageDecoder decoder;
    @SuppressWarnings("unused")
    private long messageLimit;
    private long nextTickMillis;
    private long lastLmMillis;
    
    private SpamhausClient shClient;
    private CymruClient    tcClient;
    
    // Calculate Base URI the Grizzly HTTP server will listen on
    public static URI getBaseUri() {
        String ip = System.getenv("IP");
        //if (ip == null) ip = "[::]";
        if (ip == null) ip = "0.0.0.0";
        
        String port = System.getenv("PORT");
        if (port == null) port = "8080";
        
        String baseUri = "http://" + ip + ":" + port + "/";
        return URI.create(baseUri);
    }
    
    public static boolean isTracingEnabled() {
        boolean isTracingEnabled = System.getProperties().containsKey("analytics.debug");
        return isTracingEnabled;
    }
    
    public AnalyticsServer() {
    }
    
    public void loadThreads() {
        threadFactory = new EngineThreadFactory();
        rejectionHandler = new EngineRejectionHandler();
        
        executorQueue = new ArrayBlockingQueue<Runnable>(6144);
        executor =
            new ThreadPoolExecutor(THREAD_COUNT, THREAD_COUNT, 0, TimeUnit.SECONDS,
            executorQueue,
            threadFactory, rejectionHandler);
        executor.allowCoreThreadTimeOut(false);
        while (executor.getPoolSize() < executor.getCorePoolSize()) {
            executor.prestartCoreThread();
        }
    }
    
    public void loadEsper(long currentTime) {
        log.info("starting Esper engine");
        
        config = new Configuration();
        config.configure("esper.cfg.xml");
        config.getEngineDefaults().getThreading().setInternalTimerEnabled(REPLAY_MODE? false : true);
        // config.setMetricsReportingEnabled();
        esperSpi = EPServiceProviderManager.getProvider(ESPER_URI, config);
        esperSpiImpl = (EPServiceProviderImpl) esperSpi;
        esperSpiImpl.initialize(currentTime);
        esperService = esperSpi.getEPRuntime();
        LogMessageHolder.setEsperService(esperService);
        esperAdmin = esperSpi.getEPAdministrator();
        
        log.info("started Esper engine");
    }
    
    public void loadDecoder() {
        String inputType = System.getProperty("analytics.input_type", "nanomsg").toLowerCase();
        
        if (inputType.equals("lv_file")) {
            decoder = new FileMessageDecoder(FileMessageDecoder.TEST_LV_PATH);
            REPLAY_MODE = true;
        }
        else if (inputType.equals("nanomsg")) {
            decoder = new NanomsgMessageDecoder("tcp://0.0.0.0:31337", ChannelAction.ACCEPT);
        }
        else if (inputType.equals("socket")) {
            decoder = new SocketMessageDecoder("udp://0.0.0.0:31337", ChannelAction.ACCEPT);
        }
        else {
            throw new IllegalArgumentException("unexpected Esper input type " + inputType);
        }
        
        if (REPLAY_MODE) {
            // messageLimit = 10 * 60 * 5_000;
            // decoder.setLimit(messageLimit);
        }
    }
    
    private String getFullClassName(String clazz) {
        if (!clazz.contains(".")) return this.getClass().getPackage().getName() + "." + clazz;
        else return clazz;
    }
    
    private static final Pattern LISTENER_EPL = Pattern.compile("^\\s*(LISTENER|SUBSCRIBER)\\s*(.*?)\\s*$", Pattern.CASE_INSENSITIVE);
    
    public void loadStatements() {
        int i = 0;
        try {
            // XXX: this is an ugly hard-coded value
            statements = Utils.getSqlStatements(getClass(), "EsperEngine.sql");
            statementModels = new HashMap<String, EPStatementObjectModel>(512);
            String epl, nextEpl;
            
            for (/* nothing */; i < statements.size(); ++i) {
                epl     = statements.get(i);
                nextEpl = i < statements.size() - 1 ? statements.get(i + 1) : null;
                String listenerClass = null, subscriberClass = null, className = null;
                
                if (nextEpl != null) {
                    Matcher eplMatcher = LISTENER_EPL.matcher(nextEpl);
                    if (eplMatcher.matches()) {
                        log.debug("detected listener statement {}", epl);
                        String type = eplMatcher.group(1).toLowerCase();
                        className = eplMatcher.group(2);
                        className = getFullClassName(className);
                        if (type.equals("listener")) {
                            listenerClass = className;
                        }
                        else if (type.equals("subscriber")) {
                            subscriberClass = className;
                        }
                        else {
                            throw new IllegalArgumentException("invalid listener EPL [" + nextEpl + "]");
                        }
                        /* increment index beyond the next SQL since it is tied to this SQL */
                        ++i;
                    }
                }
                
                EPStatementObjectModel statementModel = esperAdmin.compileEPL(epl);
                EPStatement statement = esperAdmin.create(statementModel);
                String eplName = statement.getName();
                statementModels.put(eplName, statementModel);
                
                if (subscriberClass != null) {
                    log.debug("subscriber class name {}", subscriberClass);
                    Object subscriber = Utils.getInstance(subscriberClass, new Object[0]);
                    statement.setSubscriber(subscriber);
                }
                
                // XXX: eventually allow multiple listeners
                if (listenerClass != null) {
                    listenerClass = getFullClassName(listenerClass);
                    log.debug("listener class name {}", listenerClass);
                    StatementAwareUpdateListener listener = Utils.getInstance(listenerClass, new StatementAwareUpdateListener[0]);
                    statement.addListener(listener);
                }
                
                if (!Utils.isAnyValid(subscriberClass, listenerClass)) {
                    log.warn("statement {} has no subscriber or listener", eplName);
                }
                
                log.info("successfully loaded statement ID {}: name: {}", i, eplName);
            }
            
            log.info("stopped loading statements at index {}", i);
        }
        catch (Exception e) {
            // removed second stacktrace to de-clutter error output
            log.error("exception loading statements into engine at index " + i /*, e*/);
            throw e;
        }
    }
    
    public void destroyEsper() {
        esperSpi.destroy();
        esperSpi = null;
    }
    
    public void loadHttpServer() {
        ResourceConfig rc = new ResourceConfig();
        rc.register(AnalyticsStatementListener.class);
        rc.register(CustomJacksonFeature.class);
        rc.register(GZipEncoder.class);
        rc.register(DeflateEncoder.class);
        rc.packages("net.mhcomputing");
        enableTracing(rc);
        
        HttpServer httpServer = GrizzlyHttpServerFactory.createHttpServer(getBaseUri(), rc, false, null, false);
        enableAccessLog(httpServer);
        enableCompression(httpServer);
        
        try {
            httpServer.start();
        }
        catch (Exception e) {
            log.error("could not start Grizzly server", e);
            throw new RuntimeException(e);
        }
        
        this.httpServer = httpServer;
    }
    
    public void destroyHttpServer() {
        httpServer.shutdownNow();
    }
    
    public void enableAccessLog(HttpServer httpServer) {
        AccessLogAppender appender = new StreamAppender(System.out);
        AccessLogFormat format = ApacheLogFormat.COMBINED;
        int statusThreshold = AccessLogProbe.DEFAULT_STATUS_THRESHOLD;
        AccessLogProbe probe = new AccessLogProbe(appender, format, statusThreshold);
        ServerConfiguration sc = httpServer.getServerConfiguration();
        sc.getMonitoringConfig().getWebServerConfig().addProbes(probe);
    }
    
    public void enableCompression(HttpServer httpServer) {
        for (NetworkListener httpListener : httpServer.getListeners()) {
            CompressionConfig cc = httpListener.getCompressionConfig();
            cc.setCompressionMode(CompressionConfig.CompressionMode.ON);
            cc.setCompressionMinSize(4096);
            // Grizzly: "Empty set means *all* mime-types are allowed to be compressed."
            cc.setCompressableMimeTypes(Collections.<String> emptySet());
        }
    }
    
    public void enableTracing(ResourceConfig rc) {
        if (!isTracingEnabled()) return;
        
        // add tracing-level console log output
        java.util.logging.Logger jlog = java.util.logging.Logger.getLogger("");
        jlog.setLevel(Level.FINEST);
        //jlog.setLevel(Level.CONFIG);
        java.util.logging.ConsoleHandler jhandler = new java.util.logging.ConsoleHandler();
        jhandler.setLevel(Level.FINEST);
        jlog.addHandler(jhandler);
        
        // add tracing-level HTTP debug header output
        Map<String, Object> properties = new HashMap<String, Object>();
        rc.register(LoggingFilter.class);
        properties.put("jersey.config.server.tracing.type", "ALL");
        // could be: SUMMARY, TRACE, VERBOSE
        properties.put("jersey.config.server.tracing.threshold", "VERBOSE");
        rc.addProperties(properties);
    }
    
    private void addReports(ConnectionTable connTable, DomainTable maliciousTable, List<? extends ThreatReport<?>> reports) {
        for (ThreatReport<?> report : reports) {
            List<Connection> connList = report.getConnections();
            connTable.addAll(connList);
            maliciousTable.putAll(report.getDomains());
        }
    }
    
    public void loadThreatReports() {
        long time = System.currentTimeMillis();
        ConnectionTable connTable = ConnectionTable.getInstance();
        if (REPLAY_MODE) {
            // DomainTable.IGNORE_WHITELIST = true;
        }
        DomainTable maliciousTable = DomainTable.getMaliciousTable();
        List<? extends ThreatReport<?>> reports;
        int totalReports = 0;
        
        shClient = new SpamhausClient();
        reports = shClient.getReports(time);
        totalReports += reports.size();
        addReports(connTable, maliciousTable, reports);
        
        tcClient = new CymruClient();
        reports = tcClient.getReports(time);
        totalReports += reports.size();
        addReports(connTable, maliciousTable, reports);
        
        log.info("Threat Report integration: reports {} conn. table size {}", totalReports, connTable.size());
        log.info("Table Contents:\n{}", connTable);
    }
    
    public void updateTimer(long currentLmMillis) {
        boolean isNextTick = currentLmMillis >= nextTickMillis;
        if (!isNextTick) return;
        
        CurrentTimeEvent timerTick = new CurrentTimeEvent(currentLmMillis);
        timerTick.setTimeInMillis(currentLmMillis);
        
        esperService.sendEvent(timerTick);
        
        Long nextTime = esperService.getNextScheduledTime();
        if (nextTime == null) nextTime = currentLmMillis + TICK_SIZE;
        log.info("nextTime {}", Utils.formatMillis(nextTime));
        nextTickMillis = nextTime;
    }
    
    public void performSleep(long currentLmMillis) {
        if (lastLmMillis == 0) { lastLmMillis = currentLmMillis; return; }
        
        long clockDelta = currentLmMillis - lastLmMillis;
        if (clockDelta <= 0) return;
        
        lastLmMillis = currentLmMillis;
        
        try {
            Thread.sleep(clockDelta);
        }
        catch (InterruptedException e) {
            log.warn("sleep failure", e);
        }
    }
    
    @Override
    public void run() {
        try {
            this.loadDecoder();
            this.loadThreatReports();
            this.loadThreads();
            
            if (!REPLAY_MODE) {
                this.loadEsper(System.currentTimeMillis());
                this.loadStatements();
                this.loadHttpServer();
            }
            
            for (LogMessage lm : decoder) {
                if (lm == null) {
                    log.warn("corrupt log message received from decoder at {}", decoder.getCurrent());
                    continue;
                }
                
                long currentLmMillis = lm.getTimeMillis();
                if (REPLAY_MODE) {
                    if (esperService == null) {
                        this.loadEsper(currentLmMillis);
                        this.loadStatements();
                        this.loadHttpServer();
                    }
                    updateTimer(currentLmMillis);
                    performSleep(currentLmMillis);
                }
                
                LogMessageHolder holder = new LogMessageHolder();
                holder.setLm(lm);
                
                if (THREAD_MODE == ThreadMode.ESPER) {
                    holder.run();
                }
                else if (THREAD_MODE == ThreadMode.EXECUTOR) {
                    executor.execute(holder);
                }
                else {
                    throw new IllegalArgumentException("unexpected thread model " + THREAD_MODE);
                }
                
                long current = decoder.getCurrent();
                if (current == 0) {
                    // avoid division by zero on i == 0
                    continue;
                }
                else if (current % 100_000 == 0) {
                    // XXX: replace with wallclock time check
                    this.displayStatistics();
                }
            }
            
            executor.shutdown();
            while (!executor.isTerminated()) {
                Thread.sleep(100);
            }
            
            this.displayStatistics();
            decoder.close();
            this.destroyHttpServer();
            this.destroyEsper();
        }
        catch (Throwable t) {
            log.error("Esper engine execution exception", t);
        }
    }
    
    private void displayStatistics() {
        decoder.displayStatistics();
        log.warn("Thread Pool Statistics: pool {}, started {}, queued {}, current {}, completed {}, spins {}",
            executor.getPoolSize(),
            executor.getActiveCount(),
            executorQueue.size(),
            executor.getTaskCount(),
            executor.getCompletedTaskCount(),
            this.rejectionHandler.getSpinCount());
    }

    private static class EngineThreadFactory
    implements ThreadFactory {
        public EngineThreadFactory() {
        }
        
        private AtomicInteger id = new AtomicInteger(0);

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, "Analytics Engine Thread #" + id.incrementAndGet());

            t.setDaemon(true);
            // change this value here if needed
            t.setPriority(Thread.NORM_PRIORITY);

            return t;
        }
    }
    
    private class EngineRejectionHandler
    implements RejectedExecutionHandler {
        public EngineRejectionHandler() {
        }
        
        private long spinCount = 0;
        public long getSpinCount() {
            return spinCount;
        }

        @Override
        public void rejectedExecution(Runnable r, ThreadPoolExecutor executor) {
            ++spinCount;
            
            try {
                boolean isAccepted = false;
                while (!isAccepted) {
                    isAccepted = executorQueue.offer(r, 120, TimeUnit.MICROSECONDS);
                }
            }
            catch (InterruptedException e) {
                log.warn("could not queue work entry");
            }
        }
    }
    
    public static void printf(String format, Object... args) {
        Formatter f = new Formatter(new StringBuilder(4 * format.length()));
        f.format(format, args);
        String message = f.toString();
        f.close();
        log.info(message);
    }
    
    public static void main(String[] args) throws Throwable {
        // XXX: work around a mysterious library path bug
        String programDir = new File(".").getCanonicalPath();
        String os = System.getProperty("os.name", "generic").toLowerCase(Locale.ENGLISH);
        if (os.contains("mac") || os.contains("darwin") || os.contains("os x")) {
            System.load(programDir + "/lib/libjnano.dylib");
        }
        else {
            System.load(programDir + "/lib/libjnano.so");
        }
        
        AnalyticsServer esperEngine = new AnalyticsServer();
        esperEngine.run();
    }
}
