-- Detects the deletion of S3 Bucket objects, either more than 20 objects in 1 hour using DeleteObject or an unknown amount using DeleteObjects
-- Fine tune according to your environment, consider applying a learning mechanism for routine user activity
SELECT
    MIN(EVENT_TIME) AS start_time,
    MAX(EVENT_TIME) AS end_time,
    USER_IDENTITY_ARN,
    USER_IDENTITY_TYPE,
    CASE
        WHEN USER_IDENTITY_TYPE = 'AssumedRole' THEN SPLIT_PART(USER_IDENTITY_ARN, '/', 2)
        ELSE NULL
    END AS USER_ROLE,
    USER_IDENTITY_ACCESS_KEY_ID,
    RECIPIENT_ACCOUNT_ID,
    EVENT_NAME,
    EVENT_SOURCE,
    SOURCE_IP_ADDRESS,
    USER_AGENT,
    BUCKET_NAME,
    SUM(CASE
        WHEN error_code IS NOT NULL THEN 0
        ELSE 1
    END) AS successful_attempts,
    SUM(CASE
        WHEN error_code IS NOT NULL THEN 1
        ELSE 0
    END) AS failed_attempts,
    COUNT(DISTINCT object_key) AS OBJECT_COUNT
FROM CLOUDTRAIL
WHERE
    EVENT_SOURCE = 's3.amazonaws.com'
    -- Exclude events initiated by AWS services
    AND SOURCE_IP_ADDRESS NOT LIKE '%.amazonaws.com'
    AND EVENT_NAME IN ('DeleteObject', 'DeleteObjects')
    -- Exclude organizational IPs
    AND SOURCE_IP_ADDRESS NOT IN (SELECT DISTINCT IP FROM organizational_ips)
    -- If possible- use a learning perioed for user roles, ip ranges and bucket names
GROUP BY
    USER_IDENTITY_ARN,
    USER_ROLE,
    USER_IDENTITY_TYPE,
    USER_IDENTITY_ACCESS_KEY_ID,
    RECIPIENT_ACCOUNT_ID,
    BUCKET_NAME,
    EVENT_NAME,
    EVENT_SOURCE,
    SOURCE_IP_ADDRESS,
    USER_AGENT,
    DATE_TRUNC('HOUR', EVENT_TIME)
HAVING
    OBJECT_COUNT > 20 OR EVENT_NAME = 'DeleteObjects'
