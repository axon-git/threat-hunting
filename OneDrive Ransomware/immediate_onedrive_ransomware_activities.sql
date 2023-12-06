WITH ACTIONS_PER_FILE AS (SELECT TIME_SLICE(EVENT_TIME::TIMESTAMP_NTZ, 5, 'SECOND', 'START') AS START_TIME,
                                 TIME_SLICE(EVENT_TIME::TIMESTAMP_NTZ, 5, 'SECOND', 'END')   AS END_TIME,
                                 RAW:SourceRelativeUrl::VARCHAR                              AS FOLDER,
                                 ARRAY_SORT(ARRAY_AGG(DISTINCT OPERATION))                   AS ALL_ACTIONS,
                                 RAW:UserAgent::VARCHAR                                      AS USER_AGENT,
                                 ARRAY_SORT(ARRAY_AGG(DISTINCT CLIENT_IP))                   AS SOURCE_IPS,
                                 ARRAY_AGG(DISTINCT RECORD_SPECIFIC_DETAILS:file_sync_bytes_committed::VARCHAR)
                                                                                            AS SYNCED_BYTES,
                                 USER_ID,
                                 OBJECT_ID
                          FROM RAW.O365_AUDIT_LOGS
                          WHERE WORKLOAD = 'OneDrive'
                          GROUP BY START_TIME, END_TIME, USER_ID, RAW:UserAgent::VARCHAR, RAW:SourceRelativeUrl::VARCHAR, OBJECT_ID
                          -- actions must contains at least one operation of content retrieval and at least one operation of file 'encryption'
                          HAVING ARRAY_SIZE(ARRAY_INTERSECTION(ALL_ACTIONS, ARRAY_CONSTRUCT('FileDownloaded', 'FileCopied', 'FileSyncDownloadedFull'))) >= 1 AND
                                  -- either no synced changes at all (0), or more than one distinct synced changes (>1)
                                 NOT ARRAY_SIZE(SYNCED_BYTES) = 1 AND
                                 (ARRAY_SIZE(ARRAY_INTERSECTION(ALL_ACTIONS, ARRAY_CONSTRUCT('FileModified', 'FileModifiedExtended', 'FileSyncUploadedFull'))) >= 1 OR
                                  ARRAY_SIZE(ARRAY_INTERSECTION(ALL_ACTIONS, ARRAY_CONSTRUCT('FileDeleted', 'FileRecycled','FileDeletedFirstStageRecycleBin', 'FileDeletedSecondStageRecycleBin'))) >= 1)
                          )
SELECT TIME_SLICE(ACTIONS_PER_FILE.START_TIME::TIMESTAMP_NTZ, 1, 'MINUTE', 'START') AS GROUP_START_TIME,
       TIME_SLICE(ACTIONS_PER_FILE.END_TIME::TIMESTAMP_NTZ, 1, 'MINUTE', 'END') AS GROUP_END_TIME,
       USER_ID,
       USER_AGENT,
       SOURCE_IPS,
       ARRAY_AGG(DISTINCT OBJECT_ID) AS INVOLVED_FILES,
       ARRAY_AGG(DISTINCT FOLDER) AS INVOLVED_FOLDERS,
       ARRAY_AGG(DISTINCT ALL_ACTIONS) AS ALL_ACTION_SEEN,
       COUNT(*) AS ALL_ACTIONS_COUNT
FROM ACTIONS_PER_FILE
GROUP BY GROUP_START_TIME, GROUP_END_TIME, USER_ID, SOURCE_IPS, USER_AGENT
-- the stage contains at least 10 files involved within a 1 minutes time range
HAVING ARRAY_SIZE(INVOLVED_FILES) >= 10
