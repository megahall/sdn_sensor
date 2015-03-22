package net.mhcomputing.sdn_sensor.utils;

import net.mhcomputing.sdn_sensor.types.LogMessage;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;

public class JsonUtils {
    private static ObjectMapper objectMapper = new ObjectMapper();
    static {
        objectMapper.setSerializationInclusion(Include.NON_NULL);
        objectMapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }

    private static ThreadLocal<ObjectReader> objectReaders =
        new ThreadLocal<ObjectReader>() {
            protected ObjectReader initialValue() {
                ObjectReader reader = objectMapper.reader();
                return reader;
            }
        };
    
    private static ThreadLocal<ObjectReader> logReaders =
        new ThreadLocal<ObjectReader>() {
            protected ObjectReader initialValue() {
                // XXX: not sure if we need more stuff here
                ObjectReader reader = objectMapper.reader(LogMessage.class);
                return reader;
            }
        };
    
    private static final String FOUR_SPACES = "    ";
    
    private static ThreadLocal<ObjectWriter> objectWriters =
        new ThreadLocal<ObjectWriter>() {
            protected ObjectWriter initialValue() {
                DefaultPrettyPrinter pp = new DefaultPrettyPrinter();
                pp.indentObjectsWith(new DefaultIndenter(FOUR_SPACES, DefaultIndenter.SYS_LF));
                pp.indentArraysWith(new DefaultIndenter(FOUR_SPACES, DefaultIndenter.SYS_LF));
                ObjectWriter writer = objectMapper.writer(pp);
                return writer;
            }
        };
    
    public static ObjectMapper getObjectMapper() {
        return objectMapper;
    }
    
    public static ObjectReader getObjectReader() {
        return objectReaders.get();
    }
    
    public static ObjectReader getLogReader() {
        return logReaders.get();
    }
    
    public static ObjectWriter getObjectWriter() {
        return objectWriters.get();
    }
}
