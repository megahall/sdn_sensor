package net.mhcomputing.sdn_sensor.engine;

import java.nio.ByteBuffer;

import net.mhcomputing.sdn_sensor.types.LogMessage;
import net.mhcomputing.sdn_sensor.utils.ByteBufferInputStream;
import net.mhcomputing.sdn_sensor.utils.ChannelAction;
import net.mhcomputing.sdn_sensor.utils.NanomsgLibrary;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NanomsgMessageDecoder extends LogMessageDecoder {
    @SuppressWarnings("unused")
    private static Logger log =
        LoggerFactory.getLogger(NanomsgMessageDecoder.class);
    
    private static NanomsgLibrary nml = NanomsgLibrary.getInstance();
    
    protected String url;
    protected ChannelAction action;
    protected ByteBuffer buffer;
    protected ByteBufferInputStream stream;
    protected int socket = -1;
    
    public NanomsgMessageDecoder(String url, ChannelAction action) {
        this.url    = url;
        this.action = action;
        this.buffer = LogMessageDecoder.createBuffer();
        this.stream = LogMessageDecoder.createStream(this.buffer);
        clear();
    }
    
    @Override
    protected void clearImpl() {
        try {
            close();
            socket = nml.getSocket(nml.NN_PULL);
            
            switch (action) {
                case ACCEPT: {
                    nml.bindSocket(socket, url);
                    break;
                }
                case CONNECT: {
                    nml.connectSocket(socket, url);
                    break;
                }
                default: {
                    break;
                }
            }
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    @Override
    protected boolean hasNextImpl() {
        // blocking read from queue: hasNext is always true
        return true;
    }
    
    @Override
    protected LogMessage nextImpl() throws Exception {
        buffer.clear();
        nml.receiveMessage(socket, buffer);
        buffer.flip();
        LogMessage lm = super.readLM(buffer, stream);
        return lm;
    }
    
    @Override
    public void close() {
        if (socket != -1) {
            nml.closeSocket(socket);
        }
    }
    
}
