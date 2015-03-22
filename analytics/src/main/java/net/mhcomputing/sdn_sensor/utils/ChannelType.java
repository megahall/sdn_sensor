package net.mhcomputing.sdn_sensor.utils;

import java.util.Locale;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum ChannelType {
    TCP,
    UDP;
    
    @JsonCreator
    public static ChannelType newInstance(String key) {
        return ChannelType.valueOf(key.toUpperCase(Locale.US));
    }

    @JsonValue
    public String getKey() {
        return this.toString().toLowerCase(Locale.US);
    }
}
