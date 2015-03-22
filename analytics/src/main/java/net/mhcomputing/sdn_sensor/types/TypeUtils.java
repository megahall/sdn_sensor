package net.mhcomputing.sdn_sensor.types;

import java.util.LinkedHashMap;
import java.util.Map;

import net.mhcomputing.sdn_sensor.utils.JsonUtils;

import com.google.common.base.Joiner;

public class TypeUtils {
    private TypeUtils() {
    }
    
    public static final String US = "\u001F";
    
    private static Joiner joiner = Joiner.on(", ").skipNulls();

    public static Map<String, Object> filterLm(LogMessage lm) {
        Map<String, Object> properties = new LinkedHashMap<String, Object>();
        
        properties.put("source", lm.getSource());
        properties.put("timeReceived", lm.getTimeMillis());
        properties.put("seqnum", lm.getSeqNum());
        properties.put("hashKey", lm.getHashKey());
        properties.put("iocId", lm.getIocId());
        properties.put("iocType", lm.getIocType());
        properties.put("iocThreatType", lm.getIocThreatType());
        properties.put("iocValue", joiner.join(lm.getIocValue(), lm.getIocIp(), lm.getIocDns()));
        
        if (lm.getConnection() != null) {
            @SuppressWarnings("unchecked")
            Map<Object, Object> connection = JsonUtils.getObjectMapper().convertValue(lm.getConnection(), LinkedHashMap.class);
            connection.put("hashKey", lm.getConnection().getHashKey());
            properties.put("connection", connection);
        }
        
        return properties;
    }
}
