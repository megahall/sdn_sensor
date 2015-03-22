package net.mhcomputing.sdn_sensor.engine;

import java.util.Calendar;
import java.util.EnumMap;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

public class FieldDecoder {
    // static utility class
    private FieldDecoder() {
    }
    
    public static TimeZone UTC = TimeZone.getTimeZone("UTC");
    
    public static Calendar convertEpochTime(long epochTimeRaw) {
        long millis = ((long) epochTimeRaw) * 1000L;
        return convertMillis(millis);
    }
    
    public static Calendar convertMillis(long millis) {
        Calendar c = Calendar.getInstance(UTC);
        c.setTimeInMillis(millis);
        return c;
    }
    
    /*
     * XXX: This breaks when proper generic types are used due to some compiler bug.
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public static String displayFlags(EnumMap flags) {
        StringBuilder sb = new StringBuilder(512);
        
        sb.append("{ ");
        
        Set<Map.Entry> entrySet = flags.entrySet();
        for (Map.Entry entry: entrySet) {
            Enum<?> k = (Enum<?>) entry.getKey();
            Number v = (Number) entry.getValue();
            if (!v.equals(0)) {
                sb.append(k).append(": ").append(v).append(", ");
            }
        }
        
        sb.append("}");
        
        return sb.toString();
    }
}
