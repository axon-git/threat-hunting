-- Detects the encryption of S3 Bucket objects using a customer managed KMS key not owned by the organization.
-- Set the request_kms_key_aws_account filter according to your needs.
-- Fine tune according to your environment, consider applying a learning mechanism or filter out known 3rd party integration roles and their KMS keys
SELECT
    MIN(event_time) AS start_time,
    MAX(event_time) AS end_time,
    event_name,
    aws_region,
    source_ip_address,
    user_agent,
    user_identity_type,
    user_identity_arn,
    bucket_name,
    SUM(CASE
        WHEN response_kms_key IS NULL OR error_code IS NOT NULL THEN 0
        ELSE 1
    END) AS successful_attempts,
    SUM(CASE
        WHEN response_kms_key IS NULL OR error_code IS NOT NULL THEN 1
        ELSE 0
    END) AS failed_attempts,
    COUNT(DISTINCT object_key) AS object_count
FROM CLOUDTRAIL
WHERE
    event_name IN ('CopyObject', 'PutObject', 'CreateMultipartUpload')
    -- Exclude events initiated by AWS services
    AND source_ip_address NOT LIKE '%.amazonaws.com'
    -- Exclude AWS managed keys and events where no key is used
    AND request_kms_key_alias NOT LIKE 'alias/aws/%'
    -- Exclude keys owned by the organization
    AND request_kms_key_aws_account NOT IN ('123456789012', '111122223333')
-- Group events by minute intervals, event origin attriutes and target bucket
GROUP BY
    DATE_TRUNC('HOUR', event_time),
    event_name,
    aws_region,
    source_ip_address,
    user_agent,
    user_identity_type,
    user_identity_arn,
    bucket_name