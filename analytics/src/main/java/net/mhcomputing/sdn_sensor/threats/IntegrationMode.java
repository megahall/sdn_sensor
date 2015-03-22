package net.mhcomputing.sdn_sensor.threats;

import java.util.Locale;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum IntegrationMode {
    LOCAL,
    REMOTE;
    
    @JsonCreator
    public static IntegrationMode newInstance(String key) {
        return IntegrationMode.valueOf(key.toUpperCase(Locale.US));
    }

    @JsonValue
    public String getKey() {
        return this.toString().toLowerCase(Locale.US);
    }
}
