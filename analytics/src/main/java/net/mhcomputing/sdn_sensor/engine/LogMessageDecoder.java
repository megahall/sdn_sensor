package net.mhcomputing.sdn_sensor.engine;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ReadableByteChannel;
import java.util.Iterator;

import net.mhcomputing.sdn_sensor.types.LogMessage;
import net.mhcomputing.sdn_sensor.utils.ByteBufferInputStream;
import net.mhcomputing.sdn_sensor.utils.JsonUtils;
import net.mhcomputing.sdn_sensor.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;

public abstract class LogMessageDecoder implements Iterator<LogMessage>, Iterable<LogMessage>, Closeable {
    private static Logger log =
        LoggerFactory.getLogger(LogMessageDecoder.class);
    
    public static final int       BUFFER_SIZE = 131072;
    public static final ByteOrder BYTE_ORDER  = ByteOrder.LITTLE_ENDIAN;
    
    public static ByteBuffer createBuffer() {
        ByteBuffer bb = ByteBuffer.allocateDirect(BUFFER_SIZE);
        bb.order(BYTE_ORDER);
        return bb;
    }
    
    public static ByteBufferInputStream createStream(ByteBuffer bb) {
        return new ByteBufferInputStream(bb);
    }
    
    protected long current;
    protected long limit;
    protected int  index;
    protected long start;
    protected long stop;
    protected long bytes;
    
    protected LogMessageDecoder() {
        clearThis();
    }
        
    public long getCurrent() {
        return current;
    }
    
    public long getLimit() {
        return limit;
    }
    
    public void setLimit(long limit) {
        this.limit = limit;
    }
    
    public int getIndex() {
        return index;
    }

    public long getStart() {
        return start;
    }

    public long getStop() {
        return stop;
    }
    
    private void clearThis() {
        current  = 0;
        limit    = -1;
        index    = 0;
        start    = System.currentTimeMillis();
    }
    
    public void clear() {
        clearThis();
        clearImpl();
    }
    
    protected abstract void clearImpl();
    
    @Override
    public boolean hasNext() {
        boolean hasNextResult;
        
        if (limit < 0 || current < limit) {
            hasNextResult = hasNextImpl();
        }
        else {
            hasNextResult = false;
        }
        
        if (!hasNextResult) {
            stop = System.currentTimeMillis();
        }
        
        return hasNextResult;
    }
    
    public void displayStatistics() {
        Utils.displayMemoryStats();
        
        double elapsed   = (stop != 0 ? (stop - start) : (System.currentTimeMillis() - start)) / 1000.0;
        double rate      = elapsed == 0 ? 0 : (current * 1.0) / elapsed;
        double data      = bytes / 1_048_576.0;
        double dataRate  = elapsed == 0 ? 0 : data / elapsed;
        
        Utils.wprintf(log, "LogMessageDecoder Statistics:");
        Utils.wprintf(log, "%09d messages in %06.3f secs.", current, elapsed);
        Utils.wprintf(log, "%05.3f messages / sec.", rate);
        Utils.wprintf(log, "%03.3f MB / sec.", dataRate);
        Utils.wprintf(log, "%09d input streams", index + 1);
    }
    
    protected abstract boolean hasNextImpl();

    @Override
    public LogMessage next() {
        try {
            if (current == 0) start = System.currentTimeMillis();
            
            LogMessage lm = nextImpl();
            ++current;
            
            return lm;
        }
        catch (Exception e) {
            log.error("could not decode log message " + getContext(), e);
            throw new RuntimeException(e);
        }
    }
    
    protected abstract LogMessage nextImpl() throws Exception;

    @Override
    public void remove() {
        throw new UnsupportedOperationException("cannot call remove() on LogMessageDecoder");
    }
    
    @Override
    public Iterator<LogMessage> iterator() {
        return this;
    }
    
    public abstract void close();
    
    public String getContext() {
        return "decoder index " + index + " current " + current;
    }
    
    public LogMessage readLM(ByteBuffer buffer, ByteBufferInputStream stream)
        throws IOException, JsonProcessingException {
        this.bytes += buffer.remaining();
        
        LogMessage lm = JsonUtils.getLogReader().readValue(stream);
        lm.setTimeMillis(System.currentTimeMillis());
        
        return lm;
    }
    
    public LogMessage readLV(ReadableByteChannel channel, ByteBuffer buffer, ByteBufferInputStream stream)
        throws IOException, IllegalAccessException, InstantiationException {
        int rv;
        
        buffer.clear().limit(4);
        rv = channel.read(buffer);
        if (rv != 4) {
            log.info("detected EOF while reading length");
            return null;
        }
        buffer.flip();
        int  length  = buffer.getInt();
        
        buffer.clear().limit(8);
        rv = channel.read(buffer);
        if (rv != 8) {
            log.warn("detected EOF while reading millis");
            return null;
        }
        buffer.flip();
        long millis  = buffer.getLong();
        
        log.trace("attempt to read length {}", length);
        buffer.clear().limit(length);
        rv = channel.read(buffer);
        if (rv != length) {
            log.warn("detected EOF while reading message");
            return null;
        }
        buffer.flip();
        
        LogMessage lm = readLM(buffer, stream);
        lm.setTimeMillis(millis);
        
        return lm;
    }    
}
