-- the query detects plain text gcp private key pairs on EDR agents, based on the key pair naming convention


WITH GCP_PROJECT_NAME AS (
    SELECT DISTINCT PROJECT_ID
    FROM RAW.GCP_AUDIT
    WHERE PROJECT_ID IS NOT NULL
      AND EVENT_TIME > CURRENT_TIMESTAMP - INTERVAL '20 days'
)

SELECT EVENT_TIME,
       AGENT_ID,
       DEVICE_PLATFORM,
       PARENT_PROCESS_NAME,
       INITIATING_PROCESS_NAME,
       INITIATING_PROCESS_COMMANDLINE,
       TARGET_FILE_NAME,
       TARGET_FILE_PATH,
       TARGET_FILE_EXTENSION,
       TARGET_FILE_HASH_SHA256,
       TARGET_FILE_ACTION
FROM INVESTIGATION.EDR_FILE_EVENTS 
        JOIN GCP_PROJECT_NAME ON  REGEXP_LIKE(EDR_FILE_EVENTS.TARGET_FILE_NAME, GCP_PROJECT_NAME.PROJECT_ID || '-[a-z0-9]{12}\.json') = TRUE
   WHERE EVENT_TIME > CURRENT_TIMESTAMP - INTERVAL '20 days'
     AND TARGET_FILE_EXTENSION='json'
