-- Threat: Data Exfiltration / C2 Communication (VPC Flow Logs)
-- MITRE ATT&CK: T1041 (Exfiltration Over C2 Channel)
-- Detects unusually high outbound data volume transfers to non-RFC1918 public IP addresses.

SELECT 
    srcaddr,
    dstaddr,
    dstport,
    protocol,
    SUM(bytes) / (1024 * 1024) AS transferred_megabytes,
    SUM(packets) AS total_packets,
    COUNT(*) AS flow_count
FROM "security_detection_db"."vpc_flow_logs"
WHERE 
    action = 'ACCEPT'
    -- Exclude private destination ranges (RFC1918)
    AND NOT (
        dstaddr LIKE '10.%'
        OR dstaddr LIKE '192.168.%'
        OR dstaddr LIKE '172.16.%'
        OR dstaddr LIKE '172.17.%'
        OR dstaddr LIKE '172.18.%'
        OR dstaddr LIKE '172.19.%'
        OR dstaddr LIKE '172.2%.%'
        OR dstaddr LIKE '172.30.%'
        OR dstaddr LIKE '172.31.%'
    )
GROUP BY 
    srcaddr, 
    dstaddr, 
    dstport, 
    protocol
HAVING SUM(bytes) >= 104857600 -- Transferred more than 100MB
ORDER BY transferred_megabytes DESC
LIMIT 20;
