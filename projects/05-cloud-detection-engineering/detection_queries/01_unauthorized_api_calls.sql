-- Threat: Discovery / Privilege Escalation Probing
-- MITRE ATT&CK: T1078 (Valid Accounts), T1087 (Account Discovery)
-- Detects anomalous spikes of AccessDenied or UnauthorizedOperation events per identity/IP.

SELECT 
    useridentity.arn AS actor_arn,
    sourceipaddress,
    eventsource,
    eventname,
    errorcode,
    COUNT(*) AS failure_count,
    MIN(eventtime) AS first_seen,
    MAX(eventtime) AS last_seen
FROM "security_detection_db"."cloudtrail_logs"
WHERE 
    errorcode IN ('AccessDenied', 'UnauthorizedOperation', 'Client.UnauthorizedOperation')
    AND eventtime >= date_add('day', -7, now())
GROUP BY 
    useridentity.arn,
    sourceipaddress,
    eventsource,
    eventname,
    errorcode
HAVING COUNT(*) >= 5
ORDER BY failure_count DESC;
