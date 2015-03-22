package net.mhcomputing.sdn_sensor.threats;

import java.util.Locale;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum DnsType {
    A          (1),
    NS         (2),
    CNAME      (5),
    SOA        (6),
    PTR       (12),
    HINFO     (13),
    MX        (15),
    TXT       (16),
    AAAA      (28),
    AXFR     (252),
    ANY      (255),
    NXDOMAIN   (3);
    
    private DnsType(int ordinal) {
        this.ordinal = ordinal;
    }
    
    private int ordinal;
    
    public int getOrdinal() {
        return this.ordinal;
    }
    
    public boolean isNameResponse() {
        return (this == NS || this == CNAME || this == SOA || this == PTR || this == MX);
    }
    
    @JsonCreator
    public static DnsType newInstance(String key) {
        return DnsType.valueOf(key.toUpperCase(Locale.US));
    }

    @JsonValue
    public String getKey() {
        return this.toString().toLowerCase(Locale.US);
    }
}
