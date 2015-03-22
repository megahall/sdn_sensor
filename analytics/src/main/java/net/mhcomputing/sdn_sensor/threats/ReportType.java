package net.mhcomputing.sdn_sensor.threats;

import java.util.Locale;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum ReportType {
    CIDR,
    DNS,
    SPAMHAUS,
    GOOGLE_SAFE_BROWSING;
    
    @JsonCreator
    public static ReportType newInstance(String key) {
        return ReportType.valueOf(key.toUpperCase(Locale.US));
    }

    @JsonValue
    public String getKey() {
        return this.toString().toLowerCase(Locale.US);
    }
}
