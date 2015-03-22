package net.mhcomputing.sdn_sensor.utils;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Formatter;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import javax.management.MBeanServer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.espertech.esper.client.EventType;
import com.espertech.esper.event.map.MapEventBean;

@SuppressWarnings("unused")
public class Utils {
    private static Logger log =
        LoggerFactory.getLogger(Utils.class);
    
    public static final TimeZone UTC    = TimeZone.getTimeZone("UTC");
    public static final String   INDENT = "    ";
    
    private static Runtime jvm = Runtime.getRuntime();
    private static MBeanServer mbeanServer = ManagementFactory.getPlatformMBeanServer();
    private static MemoryMXBean memoryMbean = ManagementFactory.getMemoryMXBean();
        
    private Utils() {
    }
    
    /**
     * XXX: This is a very dangerous function!
     * 
     * It should not be used inside a JVM that performs multiple different types
     * of operations for different users or applications.
     * 
     * See http://bugs.java.com/view_bug.do?bug_id=4724038 .
     */
    public static void unmapBuffer(FileChannel fileChannel, MappedByteBuffer bb) throws Exception {
        Class<?> fileChannelClass = fileChannel.getClass();
        
        Class<?>[] argTypeList = new Class[] { java.nio.MappedByteBuffer.class };
        Object[] argList = new Object[] { bb };
        
        Method unmapMethod = fileChannelClass.getDeclaredMethod("unmap", argTypeList);
        
        unmapMethod.setAccessible(true);
        unmapMethod.invoke(null, argList);
    }
    
    public static void destroyBuffer(ByteBuffer bb) {
        if (!bb.isDirect()) throw new IllegalArgumentException("method requires direct byte buffer");
        
        try {
            Method cleanerMethod = bb.getClass().getMethod("cleaner");
            cleanerMethod.setAccessible(true);
            Object cleaner = cleanerMethod.invoke(bb);
            Method cleanMethod = cleaner.getClass().getMethod("clean");
            cleanMethod.setAccessible(true);
            cleanMethod.invoke(cleaner);
        }
        catch (Exception e) {
        }
    }
    
    private static ThreadLocal<SimpleDateFormat> dateFormatters =
        new ThreadLocal<SimpleDateFormat>() {
            protected SimpleDateFormat initialValue() {
                SimpleDateFormat sdf = new SimpleDateFormat("EEE MMM dd HH:mm:ss.SSS yyyy zzz");
                sdf.setTimeZone(UTC);
                return sdf;
            }
    };
    
    private static ThreadLocal<SimpleDateFormat> iso8601Formatters =
        new ThreadLocal<SimpleDateFormat>() {
            protected SimpleDateFormat initialValue() {
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mmZ");
                sdf.setTimeZone(UTC);
                return sdf;
            }
    };
    
    private static ThreadLocal<NumberFormat> numberFormatters =
        new ThreadLocal<NumberFormat>() {
            protected NumberFormat initialValue() {
                NumberFormat nf = NumberFormat.getNumberInstance();
                return nf;
            }
    };
    
    /*
     * Create date string in this format:
     * 
     * Fri Feb 14 18:35:34 2014 GMT
     * 
     * Note: SimpleDateFormat is not thread-safe.
     */
    public static String formatCalendar(Calendar c) {
        SimpleDateFormat sdf = dateFormatters.get();
        return sdf.format(c.getTime());
    }
    
    public static String formatDate(Date d) {
        SimpleDateFormat sdf = dateFormatters.get();
        return sdf.format(d);
    }
    
    public static String formatMillis(long millis) {
        SimpleDateFormat sdf = dateFormatters.get();
        return sdf.format(new Date(millis));
    }
    
    public static String formatIso8601(long millis) {
        SimpleDateFormat sdf = iso8601Formatters.get();
        return sdf.format(new Date(millis));
    }
    
    public static String formatNumber(Number n) {
        return numberFormatters.get().format(n);
    }
    
    private static final double BYTES_PER_MB = 1_048_576.0;
    
    /*
     * Display JVM memory usage statistics for benchmarking.
     * 
     * Note: NumberFormat is not thread-safe.
     */
    public static void displayMemoryStats() {
        NumberFormat nf    = numberFormatters.get();
        
        MemoryUsage usage  = memoryMbean.getHeapMemoryUsage();
        
        double freeMemory      = jvm.freeMemory()  / BYTES_PER_MB;
        double totalMemory     = jvm.totalMemory() / BYTES_PER_MB;
        double maxMemory       = jvm.maxMemory()   / BYTES_PER_MB;
        double usedMemory      = totalMemory - freeMemory;
        double committedMemory = usage.getCommitted() / BYTES_PER_MB;
        double useRatio        = usedMemory / committedMemory * 100.0;
        
        String free        = nf.format(freeMemory);
        String total       = nf.format(totalMemory);
        String max         = nf.format(maxMemory);
        String used        = nf.format(usedMemory);
        String ratio       = nf.format(useRatio);
        String committed   = nf.format(committedMemory);
        
        log.info("JVM Memory Statistics: max: {} MB, used: {} MB ({}%), committed: {} MB, total: {} MB, free: {} MB.",
            max, used, ratio, committed, total, free);
    }
    
    public static List<String> getSqlStatements(Class<?> sourceClass, String statementsPath) {
        try {
            // XXX: work around weird bug loading Resource
            InputStream       statementStream       = sourceClass.getResourceAsStream(statementsPath);
            Reader            statementStreamReader = new InputStreamReader(statementStream);
            BufferedReader    statementReader       = new BufferedReader(statementStreamReader);
            String            statements            = SqlUtils.readScript(statementReader);
            ArrayList<String> statementList         = new ArrayList<String>(128);
            
            SqlUtils.splitSqlScript(statements, ';', statementList);
            return statementList;
        }
        catch (Exception e) {
            log.error("could not load SQL statements", e);
            throw new RuntimeException(e);
        }
    }
    
    public static boolean isValid(Object... args) {
        boolean isValid = true;
        
        for (Object object: args) {
            if (object == null) { isValid = false; break; }
        }
        
        return isValid;
    }
    
    public static boolean isAnyValid(Object... args) {
        boolean isValid = false;
        
        for (Object object: args) {
            if (object != null) { isValid = true; break; }
        }
        
        return isValid;
    }
    
    @SafeVarargs
    public static <T> T getFirstValid(T... args) {
        for (T object: args) {
            if (object != null) return object;
        }
        return null;
    }
    
    @SafeVarargs
    public static <T> List<T> getAllValid(T... args) {
        List<T> allValid = new ArrayList<T>(args.length);
        
        for (T object: args) {
            if (object != null) allValid.add(object);
        }
        return allValid;
    }
    
    public static String trim(String s) {
        if (s == null) return null;
        else return s.trim();
    }
    
    @SuppressWarnings("unchecked")
    public static <T> T getInstance(String name, T[] type) {
        try {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            Class<T> clazz = (Class<T>) cl.loadClass(name);
            T instance = clazz.newInstance();
            return instance;
        }
        catch (Exception e) {
            log.error("could not load create instance of class {}", name);
            throw new RuntimeException(e);
        }
    }
    
    public static InputStream getResource(String name, Class<?> type) {
        try {
            ClassLoader cl = type.getClassLoader();
            InputStream resource = cl.getResourceAsStream(name);
            return resource;
        }
        catch (Exception e) {
            log.error("could not load create instance of class {}", name);
            throw new RuntimeException(e);
        }
    }
    
    public static BufferedReader getResourceReader(String name, Class<?> type) {
        try {
            InputStream resource = getResource(name, type);
            InputStreamReader reader = new InputStreamReader(resource);
            BufferedReader buffered = new BufferedReader(reader);
            return buffered;
        }
        catch (Exception e) {
            log.error("could not load create instance of class {}", name);
            throw new RuntimeException(e);
        }
    }
    
    public static String displayMapEvent(MapEventBean event) {
        return displayMapEvent(event, INDENT);
    }
    
    // XXX: this is not efficient but it's helpful for debugging
    public static String displayMapEvent(MapEventBean event, String indent) {
        StringBuilder sb = new StringBuilder(2048);
        
        Map<String, Object> eventProps = event.getProperties();
        EventType eventType = event.getEventType();
        String[] keys = eventType.getPropertyNames();
        Arrays.sort(keys);
        
        for (String key : keys) {
            Object value = eventProps.get(key);
            Class<?> clazz = eventType.getPropertyType(key);
            
            sb.append(indent).append("key [").append(key).append("] value [");
            
            if (value == null) {
                sb.append("null");
            }
            else if (Number.class.isAssignableFrom(clazz)) {
                sb.append(Utils.formatNumber((Number) value));
            }
            else if (Calendar.class.isAssignableFrom(clazz)) {
                sb.append(Utils.formatCalendar((Calendar) value));
            }
            else if (Date.class.isAssignableFrom(clazz)) {
                sb.append(Utils.formatDate((Date) value));
            }
            else {
                sb.append(value);
            }
            
            sb.append("]\n");
        }
        
        return sb.toString();
    }
    
    public static String displayStackTrace() {
        return displayStackTrace(null);
    }
    
    public static String displayStackTrace(StackTraceElement[] stack) {
        StringBuilder sb = new StringBuilder(256);
        Formatter f = new Formatter(sb);
        
        if (stack == null) stack = Thread.currentThread().getStackTrace();

        sb.append("stack trace:\n");

        for (StackTraceElement ste : stack) {
            String[] classInfo = ste.getClassName().split("\\.", -1);

            sb.append("\t");
            sb.append(classInfo[classInfo.length - 1]);
            sb.append(".");
            sb.append(ste.getMethodName());
            sb.append(" (");
            sb.append(ste.getClassName());
            sb.append(".java");
//            sb.append(ste.getFileName());
            sb.append(":");
            sb.append(ste.getLineNumber());
            sb.append(")\n");
        }
        
        String rv = sb.toString();
        f.close();
        
        return sb.toString();
    }
    
    private static final Set<Class<?>> PRIMITIVE_TYPES = new HashSet<Class<?>>();
    static {
        PRIMITIVE_TYPES.add(Boolean.class);
        PRIMITIVE_TYPES.add(Byte.class);
        PRIMITIVE_TYPES.add(Character.class);
        PRIMITIVE_TYPES.add(Short.class);
        PRIMITIVE_TYPES.add(Integer.class);
        PRIMITIVE_TYPES.add(Long.class);
        PRIMITIVE_TYPES.add(Float.class);
        PRIMITIVE_TYPES.add(Double.class);
        PRIMITIVE_TYPES.add(Void.class);
        
        PRIMITIVE_TYPES.add(Object.class);
        PRIMITIVE_TYPES.add(Number.class);
        PRIMITIVE_TYPES.add(String.class);
        PRIMITIVE_TYPES.add(Class.class);
        PRIMITIVE_TYPES.add(Package.class);
    }
    
    // XXX: see which method works better
    public static boolean isPrimitiveType(Class<?> clazz) {
        return clazz.getName().startsWith("java.lang");
        // return PRIMITIVE_TYPES.contains(clazz);
    }

    public static void dprintf(Logger log, String format, Object... args) {
        if (!log.isDebugEnabled()) return;
        Formatter f = new Formatter(new StringBuilder(4 * format.length()));
        f.format(format, args);
        String message = f.toString();
        f.close();
        log.debug(message);
    }

    public static void wprintf(Logger log, String format, Object... args) {
        if (!log.isWarnEnabled()) return;
        Formatter f = new Formatter(new StringBuilder(4 * format.length()));
        f.format(format, args);
        String message = f.toString();
        f.close();
        log.warn(message);
    }
}
