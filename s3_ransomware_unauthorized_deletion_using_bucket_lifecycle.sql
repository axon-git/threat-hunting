-- Detects the configuration of an S3 Bucket Lifecycle rule to a short expiration time with status enabled that is not initiated by an AWS service
-- Fine tune according to your environment
SELECT
    EVENT_TIME,
    USER_IDENTITY_ARN,
    USER_IDENTITY_USER_NAME,
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
    REQUEST_PARAMETERS:LifecycleConfiguration:Rule:Expiration:Days AS expiration_days,
    REQUEST_PARAMETERS:LifecycleConfiguration:Rule:Status AS status,
    ERROR_CODE
FROM raw.AWS_CLOUDTRAIL
WHERE
    EVENT_SOURCE = 's3.amazonaws.com'
    -- Exclude AWS service IPs
    AND SOURCE_IP_ADDRESS NOT LIKE '%.amazonaws.com'
    AND EVENT_NAME = 'PutBucketLifecycle'
    -- Check for short expiration period and enabled status
    AND expiration_days < 7
    AND status = 'Enabled'