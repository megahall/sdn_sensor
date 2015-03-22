package net.mhcomputing.sdn_sensor.threats;

import java.util.List;

import net.mhcomputing.sdn_sensor.utils.DomainTable;

public interface ThreatReport<T> {
    public void read(String context, long createdTime, T reportRaw);
    public List<Connection> getConnections();
    public DomainTable getDomains();
    public int size();
    public String toString();
}
