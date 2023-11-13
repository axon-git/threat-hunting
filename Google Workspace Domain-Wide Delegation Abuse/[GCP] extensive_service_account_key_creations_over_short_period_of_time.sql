-- The thesis looks for extensive service account private key creations over a short period of time (1 hour table) which can indicate an automatic attacking activity to find Service Accounts with DWD functionality. This thesis is specifically based on Delefriend characteristics. 

SELECT
       MIN(EVENT_TIME)      EARLIEST,
       MAX(EVENT_TIME)      LATEST,
       COUNT(*)             COUNTER,
       COUNT(DISTINCT RESOURCE:labels:unique_id ) DISTINCT_SERVICE_ACCOUNTS,
       date_trunc('hour', EVENT_TIME) as TUMBLE_HOUR,
       PROJECT_ID           GCP_PROJECT_ID,
       PRINCIPAL_EMAIL      GCP_CALLER_EMAIL,
       CALLER_IP            SA_CREATION_CALLER_IP,
       CALLER_USER_AGENT    SA_CREATION_USER_AGENT,
       -- the OAuth client ID representation
       ARRAY_AGG(DISTINCT RESOURCE:labels:unique_id) SERVICE_ACCOUNT_OAUTH_CLIENT_IDS,
       SPLIT_PART(method_name, '.', -1) STRIP_METHOD_NAME,
       -- the SA's expiration date, by default unlimited (9999-12-31 23:59:59)
       TO_TIMESTAMP_NTZ(PROTO_PAYLOAD:response:valid_before_time:seconds::integer)  as SA_EXPIRATION_DATE,
        -- the private key format, by default is GOOGLE_CREDENTIALS_FILE (Google's SA json)
        ARRAY_AGG(DISTINCT CASE WHEN  PROTO_PAYLOAD:request:private_key_type  = 0 THEN 'UNSPECIFIED'
             WHEN  PROTO_PAYLOAD:request:private_key_type  = 1 THEN 'PKCS12_FILE'
             WHEN PROTO_PAYLOAD:request:private_key_type  = 2  THEN 'GOOGLE_CREDENTIALS_FILE'
             END)                                                                as SA_PRIVATE_KEY_TYPE,
        ARRAY_AGG(DISTINCT CASE WHEN PROTO_PAYLOAD:response:key_type = 0 THEN 'KEY_TYPE_UNSPECIFIED'
             WHEN PROTO_PAYLOAD:response:key_type = 1 THEN 'USER_MANAGED'
             WHEN PROTO_PAYLOAD:response:key_type = 2 THEN 'SYSTEM_MANAGED'
             END)                                                                as SA_KEY_MANGMANET_CONFIG,
        ARRAY_AGG(DISTINCT CASE WHEN PROTO_PAYLOAD:response:key_origin = 0 THEN 'ORIGIN_UNSPECIFIED'
             WHEN PROTO_PAYLOAD:response:key_origin = 1 THEN 'USER_PROVIDED'
             WHEN PROTO_PAYLOAD:response:key_origin = 2 THEN 'GOOGLE_PROVIDED'
             END)                                                                as SA_KEY_ORIGIN
   FROM RAW.GCP_AUDIT
  WHERE STRIP_METHOD_NAME = 'CreateServiceAccountKey'
    AND EVENT_TIME > dateadd(day, -60, current_timestamp)
  GROUP BY ALL
  -- adjust threshold
HAVING (COUNTER > 2 OR DISTINCT_SERVICE_ACCOUNTS > 1)
