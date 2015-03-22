package net.mhcomputing.sdn_sensor.threats;

import java.util.Locale;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum ConnectionType {
    CIDR_SRC,
    CIDR_DST,
    IP,
    ICMP,
    TCP,
    UDP,
    DNS,
    URL;
    
    public boolean isIpBased() {
        return (this == IP || this == ICMP || this == TCP || this == UDP);
    }
    
    public boolean isCidrBased() {
        return (this == CIDR_SRC || this == CIDR_DST);
    }
    
    @JsonCreator
    public static ConnectionType newInstance(String key) {
        return ConnectionType.valueOf(key.toUpperCase(Locale.US));
    }

    @JsonValue
    public String getKey() {
        return this.toString().toLowerCase(Locale.US);
    }
}
