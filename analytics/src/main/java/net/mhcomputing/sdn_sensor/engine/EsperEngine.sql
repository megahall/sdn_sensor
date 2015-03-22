@Name("TopContext")
CREATE CONTEXT TopContext START @now END AFTER 60 seconds;

@Name("HashKeyContext")
CREATE CONTEXT HashKeyContext
INITIATED BY distinct(connection.ipHashKey) LogMessage(self=false) as first_event
TERMINATED AFTER 60 seconds;

@Name("MatchPatternCorrelation")
CONTEXT HashKeyContext
SELECT
    context.first_event, last(*) as last_event, count(*) as repeat_count
FROM LogMessage(self = false, connection.ipHashKey = context.first_event.connection.ipHashKey)
GROUP BY connection.ipHashKey
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("LogMessageRate")
CONTEXT TopContext
SELECT
    COUNT(*) AS sessions_per_minute,
    COUNT(*) / 60.0 AS sessions_per_second,
    context.endTime - context.startTime AS elapsed_time
FROM LogMessage
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("ReputationCorrelation")
SELECT *
FROM LogMessage
WHERE is_malicious(LogMessage.connection) = true;
LISTENER AnalyticsStatementListener;

-- Count Always:
--     sensorName: not yet
--     portId
--     seqNum: track missing ones somehow?
--     dnsName
--     source (log msg type)
--     iocId
--     iocType
--     iocThreatType
--     iocIp
--     iocValue
--     iocDns

@Name("SensorNameSum")
CONTEXT TopContext
INSERT INTO SensorNameSum
SELECT sensorName, count(*) as scount
FROM LogMessage(sensorName != null, sensorName != '')
GROUP BY sensorName;

@Name("SensorNameTop")
CONTEXT TopContext
SELECT *
FROM SensorNameSum.ext:rank(sensorName, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("IocIdSum")
CONTEXT TopContext
INSERT INTO IocIdSum
SELECT iocId, count(*) AS scount
FROM LogMessage(iocId != 0)
GROUP BY iocId;

@Name("IocIdTop")
CONTEXT TopContext
SELECT *
FROM IocIdSum.ext:rank(iocId, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("IocTypeSum")
CONTEXT TopContext
INSERT INTO IocTypeSum
SELECT iocType, count(*) AS scount
FROM LogMessage(iocType != null)
GROUP BY iocType;

@Name("IocTypeTop")
CONTEXT TopContext
SELECT *
FROM IocTypeSum.ext:rank(iocType, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("IocThreatTypeSum")
CONTEXT TopContext
INSERT INTO IocThreatTypeSum
SELECT iocThreatType, count(*) AS scount
FROM LogMessage(iocThreatType != null, iocThreatType != '')
GROUP BY iocThreatType;

@Name("IocThreatTypeTop")
CONTEXT TopContext
SELECT *
FROM IocThreatTypeSum.ext:rank(iocThreatType, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("IocValueSum")
CONTEXT TopContext
INSERT INTO IocValueSum
SELECT iocValue, count(*) AS scount
FROM LogMessage(iocValue != null, iocValue != '')
GROUP BY iocValue;

@Name("IocValueTop")
CONTEXT TopContext
SELECT *
FROM IocValueSum.ext:rank(iocValue, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("IocIpSum")
CONTEXT TopContext
INSERT INTO IocIpSum
SELECT iocIp, count(*) AS scount
FROM LogMessage(iocIp != null, iocIp != '')
GROUP BY iocIp;

@Name("IocIpTop")
CONTEXT TopContext
SELECT *
FROM IocIpSum.ext:rank(iocIp, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("IocDnsSum")
CONTEXT TopContext
INSERT INTO IocDnsSum
SELECT iocDns, count(*) AS scount
FROM LogMessage(iocDns != null, iocDns != '')
GROUP BY iocDns;

@Name("IocDnsTop")
CONTEXT TopContext
SELECT *
FROM IocDnsSum.ext:rank(iocDns, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

-- Count If Not Self:
--     hashKey *
--     connection?
--     direction?
--     ethType
--     dstMac
--     srcMac
--     dstIp
--     srcIp
--     ipProtocol
--     dstAsn
--     srcAsn
--     srcPort
--     dstPort

@Name("HashKeySum")
CONTEXT TopContext
INSERT INTO HashKeySum
SELECT hashKey, count(*) as scount
FROM LogMessage(hashKey != null, hashKey != '', self = false)
GROUP BY hashKey;

@Name("HashKeyTop")
CONTEXT TopContext
SELECT *
FROM HashKeySum.ext:rank(hashKey, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("EthTypeSum")
CONTEXT TopContext
INSERT INTO EthTypeSum
SELECT String.format("0x%04x", { ethType }) as ethType, count(*) as scount
FROM LogMessage(ethType != 0, self = false)
GROUP BY ethType;

@Name("EthTypeTop")
CONTEXT TopContext
SELECT *
FROM EthTypeSum.ext:rank(ethType, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("DstMacSum")
CONTEXT TopContext
INSERT INTO DstMacSum
SELECT dstMac, count(*) as scount
FROM LogMessage(dstMac != null, dstMac != '', self = false)
GROUP BY dstMac;

@Name("DstMacTop")
CONTEXT TopContext
SELECT *
FROM DstMacSum.ext:rank(dstMac, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("SrcMacSum")
CONTEXT TopContext
INSERT INTO SrcMacSum
SELECT srcMac, count(*) as scount
FROM LogMessage(srcMac != null, srcMac != '', self = false)
GROUP BY srcMac;

@Name("SrcMacTop")
CONTEXT TopContext
SELECT *
FROM SrcMacSum.ext:rank(srcMac, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("DstIpSum")
CONTEXT TopContext
INSERT INTO DstIpSum
SELECT dstIp, count(*) as scount
FROM LogMessage(dstIp != null, dstIp != '', self = false)
GROUP BY dstIp;

@Name("DstIpTop")
CONTEXT TopContext
SELECT *
FROM DstIpSum.ext:rank(dstIp, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("SrcIpSum")
CONTEXT TopContext
INSERT INTO SrcIpSum
SELECT srcIp, count(*) as scount
FROM LogMessage(srcIp != null, srcIp != '', self = false)
GROUP BY srcIp;

@Name("SrcIpTop")
CONTEXT TopContext
SELECT *
FROM SrcIpSum.ext:rank(srcIp, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("IpProtocolSum")
CONTEXT TopContext
INSERT INTO IpProtocolSum
SELECT ipProtocol, count(*) as scount
FROM LogMessage(ipProtocol != 0, self = false)
GROUP BY ipProtocol;

@Name("IpProtocolTop")
CONTEXT TopContext
SELECT *
FROM IpProtocolSum.ext:rank(ipProtocol, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("DstAsnSum")
CONTEXT TopContext
INSERT INTO DstAsnSum
SELECT dstAsn, count(*) as scount
FROM LogMessage(dstAsn != 0, self = false)
GROUP BY dstAsn;

@Name("DstAsnTop")
CONTEXT TopContext
SELECT *
FROM DstAsnSum.ext:rank(dstAsn, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("SrcAsnSum")
CONTEXT TopContext
INSERT INTO SrcAsnSum
SELECT srcAsn, count(*) as scount
FROM LogMessage(srcAsn != 0, self = false)
GROUP BY srcAsn;

@Name("SrcAsnTop")
CONTEXT TopContext
SELECT *
FROM SrcAsnSum.ext:rank(srcAsn, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("DstPortSum")
CONTEXT TopContext
INSERT INTO DstPortSum
SELECT ipProtocol, dstPort, count(*) as scount
FROM LogMessage(dstPort != 0, self = false)
GROUP BY ipProtocol, dstPort;

@Name("DstPortTop")
CONTEXT TopContext
SELECT *
FROM DstPortSum.ext:rank(ipProtocol, dstPort, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;

@Name("SrcPortSum")
CONTEXT TopContext
INSERT INTO SrcPortSum
SELECT ipProtocol, srcPort, count(*) as scount
FROM LogMessage(srcPort != 0, self = false)
GROUP BY srcPort;

@Name("SrcPortTop")
CONTEXT TopContext
SELECT *
FROM SrcPortSum.ext:rank(ipProtocol, srcPort, 10, scount desc)
OUTPUT snapshot WHEN terminated;
LISTENER AnalyticsStatementListener;
