-- Threat: Compromised User Credentials / Impossible Travel
-- MITRE ATT&CK: T1078 (Valid Accounts)
-- Detects identical users signing in from distinct IP addresses within a narrow window (< 60 minutes).

WITH logins AS (
    SELECT 
        useridentity.userName AS user_name,
        sourceipaddress,
        from_iso8601_timestamp(eventtime) AS event_timestamp,
        awsregion
    FROM "security_detection_db"."cloudtrail_logs"
    WHERE 
        eventname = 'ConsoleLogin'
        AND responseelements LIKE '%"ConsoleLogin":"Success"%'
        AND eventtime >= date_add('day', -3, now())
)
SELECT 
    l1.user_name,
    l1.sourceipaddress AS ip_1,
    l2.sourceipaddress AS ip_2,
    l1.event_timestamp AS time_1,
    l2.event_timestamp AS time_2,
    date_diff('minute', l1.event_timestamp, l2.event_timestamp) AS minutes_apart
FROM logins l1
JOIN logins l2 
    ON l1.user_name = l2.user_name 
    AND l1.sourceipaddress != l2.sourceipaddress
    AND l1.event_timestamp < l2.event_timestamp
    AND date_diff('minute', l1.event_timestamp, l2.event_timestamp) <= 60
ORDER BY minutes_apart ASC;
