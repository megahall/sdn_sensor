package net.mhcomputing.sdn_sensor.utils;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class ByteBufferOutputStream extends OutputStream {
    private ByteBuffer buffer;
    
    public ByteBufferOutputStream(ByteBuffer buffer) {
        this.buffer = buffer;
    }
    
    public ByteBuffer getBuffer() {
        return buffer;
    }
    
    @Override
    public void write(int b) {
        buffer.put((byte) (0x0ff & b));
    }
    
    @Override
    public void write(byte[] b) {
        buffer.put(b);
    }
    
    @Override
    public void write(byte[] b, int offset, int length) {
        buffer.put(b, offset, length);
    }
    
    @Override
    public void flush() throws IOException {
        /* XXX: does nothing for now */
        super.flush();
    }
    
    @Override
    public void close() throws IOException {
        /* XXX: does nothing for now */
        super.close();
    }
}
