package net.mhcomputing.sdn_sensor.utils;

import java.util.Locale;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum ChannelAction {
    ACCEPT,
    CONNECT;
    
    @JsonCreator
    public static ChannelAction newInstance(String key) {
        return ChannelAction.valueOf(key.toUpperCase(Locale.US));
    }

    @JsonValue
    public String getKey() {
        return this.toString().toLowerCase(Locale.US);
    }
}
