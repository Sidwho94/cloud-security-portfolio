-- Threat: Defense Evasion / Security Auditing Impairment
-- MITRE ATT&CK: T1562.001 (Impair Defenses: Disable Cloud Logs)
-- Detects attempts by adversaries to disable, delete, or reconfigure CloudTrail.

SELECT 
    eventtime,
    useridentity.arn AS actor_arn,
    sourceipaddress,
    eventname,
    requestparameters,
    errorcode
FROM "security_detection_db"."cloudtrail_logs"
WHERE 
    eventsource = 'cloudtrail.amazonaws.com'
    AND eventname IN (
        'StopLogging',
        'DeleteTrail',
        'UpdateTrail',
        'PutEventSelectors'
    )
ORDER BY eventtime DESC;
