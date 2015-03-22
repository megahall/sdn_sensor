package net.mhcomputing.sdn_sensor.engine;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

import net.mhcomputing.sdn_sensor.types.LogMessage;
import net.mhcomputing.sdn_sensor.utils.ByteBufferInputStream;
import net.mhcomputing.sdn_sensor.utils.ChannelAction;
import net.mhcomputing.sdn_sensor.utils.ChannelType;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SocketMessageDecoder extends LogMessageDecoder {
    private static Logger log =
        LoggerFactory.getLogger(SocketMessageDecoder.class);
    
    protected URI                   uri;
    protected ChannelAction         action;
    protected ChannelType           type;
    protected String                host;
    protected int                   port;
    protected InetSocketAddress     address;
    protected ByteBuffer            buffer;
    protected ByteBufferInputStream stream;
    protected SocketChannel         tsocket;
    protected ServerSocketChannel   ssocket;
    protected DatagramChannel       usocket;
    
    public SocketMessageDecoder(String uriStr, ChannelAction action) {
        this.uri     = URI.create(uriStr);
        this.action  = action;
        this.type    = ChannelType.valueOf(uri.getScheme().toUpperCase());
        this.host    = uri.getHost();
        this.port    = uri.getPort();
        this.address = new InetSocketAddress(this.host, this.port);
        this.buffer  = LogMessageDecoder.createBuffer();
        this.stream  = LogMessageDecoder.createStream(this.buffer);
        clear();
    }
    
    @Override
    protected void clearImpl() {
        close();
        try {
            switch (type) {
                case TCP: {
                    switch (action) {
                        case ACCEPT: {
                            ssocket = ServerSocketChannel.open();
                            break;
                        }
                        case CONNECT: {
                            tsocket = SocketChannel.open();
                            break;
                        }
                        default: {
                            throw new IllegalArgumentException("unexpected socket action " + action);
                        }
                    }
                    break;
                }
                case UDP: {
                    usocket = DatagramChannel.open();
                    break;
                }
                default: {
                    throw new IllegalArgumentException("unexpected socket type " + type);
                }
            }
            
            switch (action) {
                case ACCEPT: {
                    switch (type) {
                        case TCP: {
                            ssocket.bind(address);
                            tsocket = ssocket.accept();
                            break;
                        }
                        case UDP: {
                            usocket.bind(address);
                            break;
                        }
                        default: {
                            throw new IllegalArgumentException("unexpected socket type " + type);
                        }
                    }
                    break;
                }
                case CONNECT: {
                    switch (type) {
                        case TCP: {
                            tsocket.connect(address);
                            break;
                        }
                        case UDP: {
                            usocket.connect(address);
                            break;
                        }
                        default: {
                            throw new IllegalArgumentException("unexpected socket type " + type);
                        }
                    }
                    break;
                }
                default: {
                    throw new IllegalArgumentException("unexpected socket action " + action);
                }
            }
        }
        catch (IOException e) {
            log.warn("could not open log processing socket", e);
        }
    }
    
    @Override
    protected boolean hasNextImpl() {
        // blocking read from Socket: hasNext is always true
        return true;
    }
    
    @Override
    protected LogMessage nextImpl() throws Exception {
        buffer.clear();
        int rv;
        LogMessage lm = null;
        
        switch (type) {
            case TCP: {
                buffer.limit(4);
                rv = tsocket.read(buffer);
                if (rv != 4) {
                    throw new IOException("failed to read message length");
                }
                buffer.rewind();
                int length = buffer.getInt();
                buffer.clear();
                buffer.limit(length);
                rv = tsocket.read(buffer);
                if (rv != length) {
                    throw new IOException("failed to read message body");
                }
                buffer.rewind();
                lm = super.readLM(buffer, stream);
                break;
            }
            case UDP: {
                SocketAddress sa = usocket.receive(buffer);
                if (sa == null) {
                    throw new IOException("failed to read message");
                }
                buffer.rewind();
                lm = super.readLM(buffer, stream);
                break;
            }
            default: {
                throw new IllegalArgumentException("unexpected socket type " + type);
            }
        }
        
        return lm;
    }
    
    @Override
    public void close() {
        if (tsocket != null) {
            try {
                tsocket.close();
            }
            catch (IOException e) {
                log.warn("could not close tsocket", e);
            }
        }
        if (ssocket != null) {
            try {
                ssocket.close();
            }
            catch (IOException e) {
                log.warn("could not close ssocket", e);
            }
        }
        if (usocket != null) {
            try {
                usocket.close();
            }
            catch (IOException e) {
                log.warn("could not close usocket", e);
            }
        }
    }
    
}
