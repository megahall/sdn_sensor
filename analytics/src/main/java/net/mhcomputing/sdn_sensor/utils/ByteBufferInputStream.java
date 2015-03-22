package net.mhcomputing.sdn_sensor.utils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class ByteBufferInputStream extends InputStream {
    private ByteBuffer buffer;
    
    public ByteBufferInputStream() {
    }
    
    public ByteBufferInputStream(ByteBuffer buffer) {
        this.buffer = buffer;
    }
    
    public ByteBuffer getBuffer() {
        return buffer;
    }
    
    public int read() throws IOException {
        if (!buffer.hasRemaining()) return -1;
        
        return 0x0ff & buffer.get();
    }

    public int read(byte[] b) {
        return read(b, 0, b.length);
    }
    
    public int read(byte[] b, int offset, int length) {
        if (!buffer.hasRemaining()) return -1;
        
        length = Math.min(length, buffer.remaining());
        buffer.get(b, offset, length);
        
        return length;
    }
    
    public int available() throws IOException {
        return buffer.remaining();
    }
    
    @Override
    public void close() throws IOException {
        /* XXX: does nothing for now */
        super.close();
    }
}
