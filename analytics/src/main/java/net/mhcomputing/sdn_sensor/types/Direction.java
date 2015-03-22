package net.mhcomputing.sdn_sensor.types;

import java.util.Locale;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum Direction {
    RX,
    TX,
    UNKNOWN;
    
    @JsonCreator
    public static Direction newInstance(String key) {
        return Direction.valueOf(key.toUpperCase(Locale.US));
    }

    @JsonValue
    public String getKey() {
        return this.toString().toLowerCase(Locale.US);
    }
}
