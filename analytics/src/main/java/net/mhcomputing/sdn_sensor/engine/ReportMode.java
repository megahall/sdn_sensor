package net.mhcomputing.sdn_sensor.engine;

import java.util.Locale;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum ReportMode {
    NANOMSG,
    SOCKET,
    REST;
    
    public boolean isRealtime() {
        return this != REST;
    }
    
    @JsonCreator
    public static ReportMode newInstance(String key) {
        return ReportMode.valueOf(key.toUpperCase(Locale.US));
    }

    @JsonValue
    public String getKey() {
        return this.toString().toLowerCase(Locale.US);
    }
}
