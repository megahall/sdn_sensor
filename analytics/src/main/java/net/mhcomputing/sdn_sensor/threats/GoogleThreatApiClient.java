package net.mhcomputing.sdn_sensor.threats;

import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListMap;

import net.mhcomputing.sdn_sensor.utils.ByteBufferInputStream;
import net.mhcomputing.sdn_sensor.utils.ByteBufferOutputStream;
import net.mhcomputing.sdn_sensor.utils.DomainTable;
import net.mhcomputing.sdn_sensor.utils.JsonUtils;
import net.mhcomputing.sdn_sensor.utils.NanomsgLibrary;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

public class GoogleThreatApiClient implements ThreatApiClient {
    private static Logger log =
        LoggerFactory.getLogger(GoogleThreatApiClient.class);
    
    private NanomsgLibrary nml = NanomsgLibrary.getInstance();
    
    private boolean cacheEnabled = false;
    private ConcurrentMap<String, Connection> connCache = new ConcurrentSkipListMap<String, Connection>();
    private DomainTable alexaTable = DomainTable.getAlexaTable();
    
    private ThreadLocal<Integer> nmSockets =
        new ThreadLocal<Integer>() {
            protected Integer initialValue() {
                int nmSocket = nml.getSocket(nml.NN_REQ);
                nml.connectSocket(nmSocket, "tcp://127.0.0.1:7777");
                return nmSocket;
            }
    };
    
    private ThreadLocal<ByteBuffer> nmBuffers =
        new ThreadLocal<ByteBuffer>() {
            protected ByteBuffer initialValue() {
                ByteBuffer buffer = ByteBuffer.allocateDirect(65536);
                return buffer;
            }
    };
    
    private ThreadLocal<ByteBufferOutputStream> nmOutBuffers =
        new ThreadLocal<ByteBufferOutputStream>() {
            protected ByteBufferOutputStream initialValue() {
                ByteBuffer buffer = nmBuffers.get();
                ByteBufferOutputStream stream = new ByteBufferOutputStream(buffer);
                return stream;
            }
    };
    
    private ThreadLocal<ByteBufferInputStream> nmInBuffers =
        new ThreadLocal<ByteBufferInputStream>() {
            protected ByteBufferInputStream initialValue() {
                ByteBuffer buffer = nmBuffers.get();
                ByteBufferInputStream stream = new ByteBufferInputStream(buffer);
                return stream;
            }
    };
    
    public GoogleThreatApiClient(boolean cacheEnabled) {
        this.cacheEnabled = cacheEnabled;
    }
    
    @SuppressWarnings("unchecked")
    public List<Connection> getGoogleConns(long createdTime, List<String> urls) {
        List<Connection> mconns = new ArrayList<Connection>(urls.size());
        
        try {
            ObjectWriter writer = JsonUtils.getObjectWriter();
            ObjectMapper mapper = JsonUtils.getObjectMapper();
            
            Map<String, Object> request = new HashMap<String, Object>();
            request.put("urls", urls);
            
            ByteBuffer buffer = nmBuffers.get();
            ByteBufferOutputStream outStream = nmOutBuffers.get();
            ByteBufferInputStream inStream = nmInBuffers.get();
            
            buffer.clear();
            writer.writeValue(outStream, request);
            // insert UNIX newline for readability
            buffer.put((byte) 0x0A);
            buffer.flip();
            nml.sendMessage(nmSockets.get(), buffer);
            
            buffer.clear();
            nml.receiveMessage(nmSockets.get(), buffer);
            buffer.rewind();
            
            Map<String, Object> response = mapper.readValue(inStream, Map.class);
            ArrayList<String> results = (ArrayList<String>) response.get("results");
            if (results.size() != urls.size()) {
                throw new IllegalStateException("result size " + results.size() + " does not match request size " + urls.size());
            }
            
            for (int i = 0; i < results.size(); ++i) {
                String url = urls.get(i).replaceFirst("^http(?:s)?://", "");
                String[] urlParts = url.split("/", 2);
                String result = results.get(i);
                
                if (result.length() > 0) {
                    // XXX: fix hardcoded GET method on URLs if possible
                    Connection mconn = Connection.getUrlConnection(createdTime, Connection.EMPTY, 0, 0, urlParts[0], "/" + urlParts[1], "GET", "");
                    mconn.setReportType(ReportType.GOOGLE_SAFE_BROWSING);
                    mconn.setComment("GSB-" + result);
                    mconns.add(mconn);
                }
                else {
                    mconns.add(Connection.EMPTY_CONNECTION);
                }
            }
        }
        catch (Exception e) {
            log.warn("GSB API query failure", e);
        }
        
        return mconns;
    }
    
    @Override
    public List<Connection> getMalicious(Connection conn) {
        if (conn.getType() != ConnectionType.URL) {
            return Collections.emptyList();
        }
        
        String urlHost = conn.getUrlHost();
        String urlPath = conn.getUrlPath();
        
        if (alexaTable.get(urlHost, true) != null) {
            return Collections.emptyList();
        }
        
        long createdTime = conn.getCreatedTime();
        
        // XXX: bug: logs do not include HTTP or HTTPS: check both
        String httpUrl                 = "http://"  + urlHost + "/" + urlPath;
        String httpsUrl                = "https://" + urlHost + "/" + urlPath;
        
        Connection httpCached          = connCache.get(httpUrl);
        Connection httpsCached         = connCache.get(httpsUrl);
        List<Connection> cachedConns   = Connection.getAllValidConns(Arrays.asList(httpCached, httpsCached));
        if (cacheEnabled && cachedConns.size() > 0) return cachedConns;
        
        List<String> urls              = Arrays.asList(httpUrl, httpsUrl);
        List<Connection> conns         = getGoogleConns(createdTime, urls);
        safeCacheAdd(createdTime, urls, conns);
        
        return Connection.getAllValidConns(conns);
    }
    
    private void safeCacheAdd(long createdTime, List<String> urls, List<Connection> conns) {
        if (conns.size() == 0) {
            /* no connections from GSB API, do nothing */
            return;
        }
        
        if (conns.size() != urls.size()) {
            throw new IllegalStateException("conn list size " + conns.size() + " does not match url list size " + urls.size());
        }
        
        for (int i = 0; i < conns.size(); ++i) {
            String url = urls.get(i);
            Connection conn = conns.get(i);
            if (conn == null)
                conn = Connection.EMPTY_CONNECTION;
            
            connCache.put(url, conn);
        }
    }
    
    public static void main(String[] args) throws Throwable {
        GoogleThreatApiClient client = new GoogleThreatApiClient(false);
        FileChannel nullChannel = FileChannel.open(Paths.get("/dev/null"), StandardOpenOption.WRITE);
        ByteBuffer nullBuffer = ByteBuffer.allocateDirect(65536);
        ByteBufferOutputStream nullStream = new ByteBufferOutputStream(nullBuffer);
        DataOutputStream nullOutput = new DataOutputStream(nullStream);
        
        long start = System.currentTimeMillis();
        for (int i = 0; i < 20000; ++i) {
            Connection testConn = Connection.getUrlConnection(System.currentTimeMillis(), "1.1.1.1", 1111, 10000, "uwyejs.com", Connection.EMPTY, "GET", Connection.EMPTY);
            List<Connection> gsbConns = client.getMalicious(testConn);
            for (Connection gsbConn : gsbConns) {
                nullBuffer.clear();
                nullOutput.writeChars(gsbConn.toString());
                nullBuffer.flip();
                nullChannel.write(nullBuffer);
            }
        }
        long elapsed = System.currentTimeMillis() - start;
        double secs = elapsed / 1000.0;
        
        nullOutput.close();
        
        //log.info("elapsed {} gsbConns:\n{}", gsbConns);
        log.info("elapsed: {} secs.", secs);
    }
}
