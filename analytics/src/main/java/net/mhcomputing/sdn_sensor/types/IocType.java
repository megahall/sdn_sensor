package net.mhcomputing.sdn_sensor.types;

import java.util.Locale;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum IocType {
    IP,
    DOMAIN,
    URL,
    EMAIL,
    MD5,
    SHA256,
    UNKNOWN;
    
    @JsonCreator
    public static IocType newInstance(String key) {
        return IocType.valueOf(key.toUpperCase(Locale.US));
    }

    @JsonValue
    public String getKey() {
        return this.toString().toLowerCase(Locale.US);
    }
}
