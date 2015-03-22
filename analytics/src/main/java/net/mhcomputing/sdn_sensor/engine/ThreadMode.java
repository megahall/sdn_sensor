package net.mhcomputing.sdn_sensor.engine;

import java.util.Locale;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum ThreadMode {
    ESPER,
    EXECUTOR,
    DISRUPTOR;
    
    @JsonCreator
    public static ThreadMode newInstance(String key) {
        return ThreadMode.valueOf(key.toUpperCase(Locale.US));
    }

    @JsonValue
    public String getKey() {
        return this.toString().toLowerCase(Locale.US);
    }
}
