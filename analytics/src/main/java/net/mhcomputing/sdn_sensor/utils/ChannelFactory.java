package net.mhcomputing.sdn_sensor.utils;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.net.URI;
import java.nio.channels.ByteChannel;
import java.nio.channels.Channel;
import java.nio.channels.DatagramChannel;
import java.nio.channels.NetworkChannel;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ChannelFactory {
    private static Logger log =
        LoggerFactory.getLogger(ChannelFactory.class);
    
    private static final int DEFAULT_RCVBUF = 262144;
    private static final int DEFAULT_SNDBUF = 262144;
    
    private ChannelFactory() {
    }
    
    private static void setOptions(NetworkChannel nchannel) throws IOException {
        String osName = System.getProperty("os.name");
        boolean isOsX = osName.contains("OS X");
        if (!isOsX) {
            log.info("skipping option setup on platform {}", osName);
            return;
        }
        
        int prevRcvBuf = nchannel.getOption(StandardSocketOptions.SO_RCVBUF);
        int prevSndBuf = nchannel.getOption(StandardSocketOptions.SO_SNDBUF);
        log.warn("nchannel: previous: SO_RCVBUF {} SO_SNDBUF {}", prevRcvBuf, prevSndBuf);
        nchannel.setOption(StandardSocketOptions.SO_RCVBUF, DEFAULT_RCVBUF);
        nchannel.setOption(StandardSocketOptions.SO_SNDBUF, DEFAULT_SNDBUF);
        int currRcvBuf = nchannel.getOption(StandardSocketOptions.SO_RCVBUF);
        int currSndBuf = nchannel.getOption(StandardSocketOptions.SO_SNDBUF);
        log.warn("nchannel: current: SO_RCVBUF {} SO_SNDBUF {}", currRcvBuf, currSndBuf);
    }
    
    public static ByteChannel getChannel(URI uri, ChannelAction action) {
        Objects.requireNonNull(uri);
        Objects.requireNonNull(action);
        
        ChannelType       type    = ChannelType.valueOf(uri.getScheme().toUpperCase());
        String            host    = uri.getHost();
        int               port    = uri.getPort();
        InetSocketAddress address = new InetSocketAddress(host, port);
        
        SocketChannel       tchannel;
        ServerSocketChannel schannel;
        DatagramChannel     uchannel;
        
        try {
            switch (type) {
                case TCP: {
                    switch (action) {
                        case ACCEPT: {
                            schannel = ServerSocketChannel.open();
                            schannel.bind(address);
                            tchannel = schannel.accept();
                            break;
                        }
                        case CONNECT: {
                            tchannel = SocketChannel.open();
                            tchannel.connect(address);
                            break;
                        }
                        default: {
                            throw new IllegalArgumentException("unexpected channel action " + action);
                        }
                    }
                    setOptions(tchannel);
                    return tchannel;
                }
                case UDP: {
                    uchannel = DatagramChannel.open();
                    switch (action) {
                        case ACCEPT: {
                            uchannel.bind(address);
                            break;
                        }
                        case CONNECT: {
                            uchannel.connect(address);
                            break;
                        }
                        default: {
                            throw new IllegalArgumentException("unexpected channel action " + action);
                        }
                    }
                    setOptions(uchannel);
                    return uchannel;
                }
                default: {
                    throw new IllegalArgumentException("unexpected channel type " + type);
                }
            }
        }
        catch (IOException e) {
            log.warn("could not open NIO channel", e);
            throw new RuntimeException(e);
        }
    }
    
    public static ChannelType getChannelType(Channel channel) {
        Objects.requireNonNull(channel, "channel cannot be null");
        if (channel instanceof ServerSocketChannel || channel instanceof SocketChannel) {
            return ChannelType.TCP;
        }
        else if (channel instanceof DatagramChannel) {
            return ChannelType.UDP;
        }
        else {
            throw new IllegalArgumentException("unexpected channel type " + channel.getClass().getName());
        }
    }
}
