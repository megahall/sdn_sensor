package net.mhcomputing.sdn_sensor.types;

import java.util.Locale;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum LogType {
    PCAP,
    FRAME_IOC,
    DNS_RULE,
    DNS_IOC,
    UDP_SYSLOG,
    TCP_SYSLOG,
    NETFLOW_IOC;
    
    @JsonCreator
    public static LogType newInstance(String key) {
        return LogType.valueOf(key.toUpperCase(Locale.US));
    }

    @JsonValue
    public String getKey() {
        return this.toString().toLowerCase(Locale.US);
    }
}
