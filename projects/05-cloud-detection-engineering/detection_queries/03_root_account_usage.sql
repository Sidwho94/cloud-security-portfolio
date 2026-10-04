-- Threat: Root Account Activity
-- CIS AWS Foundations Benchmark: 1.1 (Avoid the use of the "root" account)
-- MITRE ATT&CK: T1078.004 (Valid Accounts: Cloud Accounts)
-- Detects any API call or console login made using the AWS root credentials.

SELECT 
    eventtime,
    eventname,
    eventsource,
    sourceipaddress,
    useragent,
    recipientaccountid,
    requestparameters
FROM "security_detection_db"."cloudtrail_logs"
WHERE 
    useridentity.type = 'Root'
    AND eventtype != 'AwsServiceEvent'
ORDER BY eventtime DESC;
