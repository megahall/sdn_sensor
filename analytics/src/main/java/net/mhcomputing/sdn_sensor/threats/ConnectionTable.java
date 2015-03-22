package net.mhcomputing.sdn_sensor.threats;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.ardverk.collection.PatriciaTrie;
import org.ardverk.collection.StringKeyAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.mhcomputing.sdn_sensor.utils.Utils;

public class ConnectionTable {
    private static Logger log =
        LoggerFactory.getLogger(ConnectionTable.class);
    
    private static final String EMPTY = Connection.EMPTY;
    
    private static ConnectionTable instance = new ConnectionTable();
    
    public static synchronized ConnectionTable getInstance() {
        return instance;
    }
    
    private ReadWriteLock tableLock;
    private Lock writeLock;
    private Lock readLock;
    private Map<String, Connection> connKeyHash;
    private PatriciaTrie<String, Connection> connSrcTrie4;
    private PatriciaTrie<String, Connection> connSrcTrie6;
    private PatriciaTrie<String, Connection> connDstTrie4;
    private PatriciaTrie<String, Connection> connDstTrie6;
    
    private ConnectionTable() {
        tableLock    = new ReentrantReadWriteLock();
        writeLock    = tableLock.writeLock();
        readLock     = tableLock.readLock();
        connKeyHash  = new HashMap<String, Connection>();
        connSrcTrie4 = new PatriciaTrie<String, Connection>(StringKeyAnalyzer.CHAR);
        connSrcTrie6 = new PatriciaTrie<String, Connection>(StringKeyAnalyzer.CHAR);
        connDstTrie4 = new PatriciaTrie<String, Connection>(StringKeyAnalyzer.CHAR);
        connDstTrie6 = new PatriciaTrie<String, Connection>(StringKeyAnalyzer.CHAR);
    }
    
    private static List<String> getEscapedHashKeys(Collection<Connection> connList) {
        List<String> hashKeys = new ArrayList<String>(connList.size());
        for (Connection conn : connList) {
            String escapedHashKey = conn.getEscapedHashKey();
            if (escapedHashKey != EMPTY) hashKeys.add(escapedHashKey);
            if (conn.getType().isIpBased()) {
                String escapedIpHashKey = conn.getEscapedIpHashKey();
                if (escapedHashKey != EMPTY) hashKeys.add(escapedIpHashKey);
            }
        }
        return hashKeys;
    }
    
    public void addAll(Collection<Connection> connList) {
        try {
            writeLock.lock();
            for (Connection conn : connList) {
                connKeyHash.put(conn.getHashKey(), conn);
                cidrAdd(conn);
            }
            if (log.isDebugEnabled()) {
                List<String> escapedHashKeys = getEscapedHashKeys(connList);
                for (String escapedHashKey : escapedHashKeys) {
                    log.debug("conn table added {}", escapedHashKey);
                }
            }
        }
        finally {
            writeLock.unlock();
        }
    }
    
    public void removeAll(Collection<Connection> connList) {
        try {
            writeLock.lock();
            for (Connection conn : connList) {
                hashRemove(conn);
                cidrRemove(conn);
            }
        }
        finally {
            writeLock.unlock();
        }
    }
    
    public void add(Connection conn) {
        try {
            writeLock.lock();
            hashAdd(conn);
            cidrAdd(conn);
        }
        finally {
            writeLock.unlock();
        }
    }
    
    /*
     * Must hold tableLock before calling this.
     */
    private void hashAdd(Connection conn) {
        String hashKey = conn.getHashKey();
        if (hashKey != EMPTY) connKeyHash.put(hashKey, conn);
        if (conn.getType().isIpBased()) {
            String ipHashKey = conn.getIpHashKey();
            if (ipHashKey != EMPTY) connKeyHash.put(ipHashKey, conn);
        }
    }
    
    /*
     * Must hold tableLock before calling this.
     */
    private void cidrAdd(Connection conn) {
        if (!conn.getType().isCidrBased()) return;
        if (conn.getType() == ConnectionType.CIDR_SRC) {
            connSrcTrie4.put(conn.getSrcCidr(), conn);
        }
        else if (conn.getType() == ConnectionType.CIDR_DST) {
            connDstTrie4.put(conn.getDstCidr(), conn);
        }
    }
    
    public void remove(Connection conn) {
        try {
            writeLock.lock();
            hashRemove(conn);
            cidrRemove(conn);
        }
        finally {
            writeLock.unlock();
        }
    }
    
    /*
     * Must hold tableLock before calling this.
     */
    private void hashRemove(Connection conn) {
        String hashKey = conn.getHashKey();
        if (hashKey != EMPTY) connKeyHash.remove(hashKey);
        if (conn.getType().isIpBased()) {
            String ipHashKey = conn.getIpHashKey();
            if (ipHashKey != EMPTY) connKeyHash.remove(ipHashKey);
        }
    }
    
    /*
     * Must hold tableLock before calling this.
     */
    private void cidrRemove(Connection conn) {
        if (!conn.getType().isCidrBased()) return;
        if (conn.getType() == ConnectionType.CIDR_SRC) {
            connSrcTrie4.remove(conn.getSrcCidr());
        }
        else if (conn.getType() == ConnectionType.CIDR_DST) {
            connDstTrie4.remove(conn.getDstCidr());
        }
    }
    
    public int size() {
        try {
            readLock.lock();
            return connKeyHash.size();
        }
        finally {
            readLock.unlock();
        }
    }

    public boolean isEmpty() {
        try {
            readLock.lock();
            return connKeyHash.isEmpty();
        }
        finally {
            readLock.unlock();
        }
    }

    public void clear() {
        try {
            writeLock.lock();
            connKeyHash.clear();
            connSrcTrie4.clear();
            connSrcTrie6.clear();
            connDstTrie4.clear();
            connDstTrie6.clear();
        }
        finally {
            writeLock.unlock();
        }
    }

    public void removeExpired(long maxAge) {
        try {
            writeLock.lock();
            Iterator<Connection> connIter = connKeyHash.values().iterator();
            while (connIter.hasNext()) {
                Connection conn = connIter.next();
                if (conn.getCreatedTime() < maxAge) {
                    connIter.remove();
                    cidrRemove(conn);
                }
            }
        }
        finally {
            writeLock.unlock();
        }
    }
    
    public Connection getMalicious(Connection conn) {
        String hashKey = conn.getHashKey();
        String ipHashKey = conn.getIpHashKey();
        Connection pconn = null, iconn = null, tsconn = null, tdconn = null;
        ConnectionType type = conn.getType();
        boolean isIpBased = type.isIpBased();
        String srcCidr = isIpBased ? conn.getSrcCidr() : null;
        String dstCidr = isIpBased ? conn.getDstCidr() : null;
        String srcKey = null;
        String dstKey = null;
        
        try {
            readLock.lock();
            
            pconn = connKeyHash.get(hashKey);
            iconn = connKeyHash.get(ipHashKey);
            if (isIpBased) {
                Map.Entry<String, Connection> srcEntry = connSrcTrie4.getFloor(srcCidr);
                srcKey = srcEntry == null ? null : srcEntry.getKey();
                tsconn = srcEntry == null ? null : srcEntry.getValue();
                
                Map.Entry<String, Connection> dstEntry = connDstTrie4.getFloor(dstCidr);
                dstKey = dstEntry == null ? null : dstEntry.getKey();
                tdconn = dstEntry == null ? null : dstEntry.getValue();
            }
        }
        finally {
            readLock.unlock();
        }
        
        if (isIpBased && !srcCidr.startsWith(srcKey)) {
            tsconn = null;
        }
        if (isIpBased && !dstCidr.startsWith(dstKey)) {
            tdconn = null;
        }
        
        return Utils.getFirstValid(tsconn, tdconn, pconn, iconn);
    }
    
    public boolean isMalicious(Connection conn) {
        return getMalicious(conn) != null;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getName());
        sb.append(": {\n");
        int i = 0;
        for (String hashKey : connKeyHash.keySet()) {
            sb.append("    entry [").append(i).append("] hash [").append(hashKey.replace(Connection.US, " ").trim()).append("]\n");
            ++i;
        }
        for (Map.Entry<String, Connection> entry : connSrcTrie4.entrySet()) {
            String cidr    = entry.getValue().getSrcIp();
            String comment = entry.getValue().getComment();
            sb.append("    entry [").append(i).append("] srcCidr [").append(cidr).append("] comment [").append(comment).append("]\n");
            ++i;
        }
        for (Map.Entry<String, Connection> entry : connDstTrie4.entrySet()) {
            String cidr    = entry.getValue().getDstIp();
            String comment = entry.getValue().getComment();
            sb.append("    entry [").append(i).append("] dstCidr [").append(cidr).append("] comment [").append(comment).append("]\n");
            ++i;
        }
        sb.append("}");
        return sb.toString();
    }
}
