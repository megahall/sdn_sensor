package net.mhcomputing.sdn_sensor.utils;

import java.nio.ByteBuffer;

import org.nanomsg.NanoLibrary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NanomsgLibrary extends NanoLibrary {
    private static Logger log =
        LoggerFactory.getLogger(NanomsgLibrary.class);
    
    private static final NanomsgLibrary nanomsgLibrary = new NanomsgLibrary();
    public static NanomsgLibrary getInstance() {
        return nanomsgLibrary;
    }
    
    public static final int DEFAULT_SNDBUF = 524288;
    public static final int DEFAULT_RCVBUF = 524288;
    
    public static final int EAGAIN;
    
    static {
        String  osName  = System.getProperty("os.name");
        boolean isOsx   = osName.contains("OS X");
        boolean isLinux = osName.contains("Linux");
        
        if (isOsx) {
            EAGAIN = 35;
        }
        else if (isLinux) {
            EAGAIN = 11;
        }
        else {
            throw new IllegalStateException("unexpected operating system");
        }
    }
    
    public NanomsgLibrary() {
        super();
    }
    
    public int getSocket(int protocol) {
        int socket = this.nn_socket(AF_SP, protocol);
        if (socket < 0) {
            String error = this.nn_strerror(this.nn_errno());
            log.warn("nanomsg socket creation error: {}: {}", this.nn_errno(), error);
            throw new NanomsgException(error);
        }
        this.setOption(socket, NN_SNDBUF, DEFAULT_SNDBUF);
        this.setOption(socket, NN_RCVBUF, DEFAULT_RCVBUF);
        return socket; 
    }
    
    public int getOption(int socket, int option) {
        Integer value = Integer.valueOf(0);
        int rc = this.nn_getsockopt_int(socket, NN_SOL_SOCKET, option, value);
        if (rc < 0) {
            String error = this.nn_strerror(this.nn_errno());
            log.warn("nanomsg option get error: {}: {}", this.nn_errno(), error);
            throw new NanomsgException(error);
        }
        return value;
    }
    
    public int setOption(int socket, int option, int value) {
        int rc = this.nn_setsockopt_int(socket, NN_SOL_SOCKET, option, value);
        if (rc < 0) {
            String error = this.nn_strerror(this.nn_errno());
            log.warn("nanomsg option set error: {}: {}", this.nn_errno(), error);
            throw new NanomsgException(error);
        }
        return rc;
    }
    
    public int bindSocket(int socket, String url) {
        int rc = this.nn_bind(socket, url);
        if (rc < 0) {
            String error = this.nn_strerror(this.nn_errno());
            log.warn("nanomsg bind error: {}: {}", this.nn_errno(), error);
            throw new NanomsgException(error);
        }
        return rc;
    }
    
    public int connectSocket(int socket, String url) {
        int rc = this.nn_connect(socket, url);
        if (rc < 0) {
            String error = this.nn_strerror(this.nn_errno());
            log.warn("nanomsg connect error: {}: {}", this.nn_errno(), error);
            throw new NanomsgException(error);
        }
        return rc;
    }
    
    public int receiveMessage(int socket, ByteBuffer buffer) {
        return receiveMessage(socket, buffer, 0);
    }
    
    public int receiveMessage(int socket, ByteBuffer buffer, int flags) {
        int rc = this.nn_recv(socket, buffer, flags);
        if (rc < 0) {
            if ((flags & NN_DONTWAIT) > 0 && this.nn_errno() == EAGAIN) {
                return rc;
            }
            String error = this.nn_strerror(this.nn_errno());
            log.warn("nanomsg receive error: {}: {}", this.nn_errno(), error);
            throw new NanomsgException(error);
        }
        return rc;
    }
    
    public int sendMessage(int socket, ByteBuffer buffer) {
        return sendMessage(socket, buffer, 0);
    }
    
    public int sendMessage(int socket, ByteBuffer buffer, int flags) {
        int rc = this.nn_send(socket, buffer, flags);
        if (rc < 0) {
            if ((flags & NN_DONTWAIT) > 0 && this.nn_errno() == EAGAIN) {
                return rc;
            }
            String error = this.nn_strerror(this.nn_errno());
            log.warn("nanomsg send error: {}: {}", this.nn_errno(), error);
            throw new NanomsgException(error);
        }
        return rc;
    }
    
    public int closeSocket(int socket) {
        int rc = this.nn_close(socket);
        if (rc < 0) {
            String error = this.nn_strerror(this.nn_errno());
            log.warn("nanomsg send error: {}: {}", this.nn_errno(), error);
            throw new NanomsgException(error);
        }
        return rc;
    }
}
