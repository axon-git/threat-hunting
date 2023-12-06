-- collection activities per file
WITH COLLECTION_ACTION AS (SELECT TIME_SLICE(EVENT_TIME::TIMESTAMP_NTZ, 5, 'SECOND', 'START') AS START_TIME,
                                  TIME_SLICE(EVENT_TIME::TIMESTAMP_NTZ, 5, 'SECOND', 'END')   AS END_TIME,
                                  MIN(EVENT_TIME)                                             AS EVENT_TIME,
                                  RAW:UserAgent::VARCHAR                                      AS USER_AGENT,
                                  ARRAY_SORT(ARRAY_AGG(DISTINCT CLIENT_IP))                   AS SOURCE_IPS,
                                  RAW:SourceRelativeUrl::VARCHAR                              AS FOLDER,
                                  ARRAY_SORT(ARRAY_AGG(DISTINCT OPERATION))                   AS ALL_ACTIONS,
                                  USER_ID,
                                  OBJECT_ID
                          FROM RAW.O365_AUDIT_LOGS
                          WHERE WORKLOAD = 'OneDrive'
                          GROUP BY START_TIME, END_TIME, USER_ID, RAW:UserAgent::VARCHAR, RAW:SourceRelativeUrl::VARCHAR, OBJECT_ID
                          -- performed actions contains at least one of the content retrieval operations
                          HAVING ARRAY_SIZE(ARRAY_INTERSECTION(ALL_ACTIONS, ARRAY_CONSTRUCT('FileDownloaded', 'FileCopied', 'FileSyncDownloadedFull'))) >= 1),
-- collection complete stage
COLLECTION_STAGE AS  (SELECT TIME_SLICE(COLLECTION_ACTION.START_TIME::TIMESTAMP_NTZ, 5, 'MINUTE', 'START') AS START_TIME,
                             TIME_SLICE(COLLECTION_ACTION.END_TIME::TIMESTAMP_NTZ, 5, 'MINUTE', 'END')     AS END_TIME,
                             ARRAY_AGG(DISTINCT OBJECT_ID)                                                 AS INVOLVED_FILES,
                             ARRAY_AGG(DISTINCT FOLDER)                                                    AS INVOLVED_FOLDERS,
                             ARRAY_AGG(DISTINCT ALL_ACTIONS)                                               AS ALL_ACTION_SEEN,
                             USER_ID,
                             USER_AGENT,
                             SOURCE_IPS
                      FROM COLLECTION_ACTION
                      GROUP BY START_TIME, END_TIME, USER_ID, SOURCE_IPS, USER_AGENT
                      -- the stage contains at least 60 files involved, and more than 1 folder within a 5 minutes time range
                      HAVING ARRAY_SIZE(INVOLVED_FILES) >= 60 AND ARRAY_SIZE(INVOLVED_FOLDERS) > 1),
-- 'encryption' activities per file
ENCRYPTION_ACTION AS (SELECT TIME_SLICE(EVENT_TIME::TIMESTAMP_NTZ, 5, 'SECOND', 'START') AS START_TIME,
                             TIME_SLICE(EVENT_TIME::TIMESTAMP_NTZ, 5, 'SECOND', 'END')   AS END_TIME,
                             MIN(EVENT_TIME)                                             AS EVENT_TIME,
                             RAW:UserAgent::VARCHAR AS USER_AGENT,
                             ARRAY_SORT(ARRAY_AGG(DISTINCT CLIENT_IP))                   AS SOURCE_IPS,
                             USER_ID,
                             OBJECT_ID,
                             RAW:SourceRelativeUrl::VARCHAR                              AS FOLDER,
                             ARRAY_SORT(ARRAY_AGG(DISTINCT OPERATION))                   AS ALL_ACTIONS
                          FROM RAW.O365_AUDIT_LOGS
                          WHERE WORKLOAD = 'OneDrive'
                          GROUP BY START_TIME, END_TIME, USER_ID, RAW:UserAgent::VARCHAR, RAW:SourceRelativeUrl::VARCHAR, OBJECT_ID
                          -- performed actions contains at least one of the content modification or deletion operations
                          HAVING ARRAY_SIZE(ARRAY_INTERSECTION(ALL_ACTIONS, ARRAY_CONSTRUCT('FileModified', 'FileModifiedExtended', 'FileSyncUploadedFull'))) >= 1 OR
                                 ARRAY_SIZE(ARRAY_INTERSECTION(ALL_ACTIONS, ARRAY_CONSTRUCT('FileDeleted', 'FileRecycled','FileDeletedFirstStageRecycleBin', 'FileDeletedSecondStageRecycleBin'))) >= 1
                          ),
-- 'encryption' complete stage
ENCRYPTION_STAGE AS  (SELECT TIME_SLICE(ENCRYPTION_ACTION.START_TIME::TIMESTAMP_NTZ, 5, 'MINUTE', 'START') AS START_TIME,
                             TIME_SLICE(ENCRYPTION_ACTION.END_TIME::TIMESTAMP_NTZ, 5, 'MINUTE', 'END')     AS END_TIME,
                             ARRAY_AGG(DISTINCT OBJECT_ID)                                                 AS INVOLVED_FILES,
                             ARRAY_AGG(DISTINCT FOLDER)                                                    AS INVOLVED_FOLDERS,
                             ARRAY_AGG(DISTINCT ALL_ACTIONS)                                               AS ALL_ACTION_SEEN,
                             USER_ID,
                             USER_AGENT,
                             SOURCE_IPS
                      FROM ENCRYPTION_ACTION
                      GROUP BY START_TIME, END_TIME, USER_ID, SOURCE_IPS, USER_AGENT
                      -- the stage contains at least 60 files involved, and more than 1 folder within a 5 minutes time range
                      HAVING ARRAY_SIZE(INVOLVED_FILES) >= 60 AND ARRAY_SIZE(INVOLVED_FOLDERS) > 1
                      )
SELECT COLLECTION_STAGE.USER_ID                       AS USER_ID,
       COLLECTION_STAGE.START_TIME                    AS COLLECTION_START_TIME,
       COLLECTION_STAGE.END_TIME                      AS COLLECTION_END_TIME,
       COLLECTION_STAGE.ALL_ACTION_SEEN               AS COLLECTION_SEEN_ACTIONS,
       ENCRYPTION_STAGE.START_TIME                    AS ENCRYPTION_START_TIME,
       ENCRYPTION_STAGE.END_TIME                      AS ENCRYPTION_END_TIME,
       ENCRYPTION_STAGE.ALL_ACTION_SEEN               AS ENCRYPTION_SEEN_ACTIONS,
       ARRAY_DISTINCT(ARRAY_CAT(ENCRYPTION_STAGE.INVOLVED_FILES, ENCRYPTION_STAGE.INVOLVED_FILES))
                                                      AS INVOLVED_FILES
FROM ENCRYPTION_STAGE
INNER JOIN COLLECTION_STAGE ON -- stages have a time difference of up to 7 days
                               ENCRYPTION_STAGE.START_TIME - interval '7 days' <= COLLECTION_STAGE.START_TIME AND
                               COLLECTION_STAGE.END_TIME <= ENCRYPTION_STAGE.END_TIME AND
                               -- the performing user is the same in both stages
                               COLLECTION_STAGE.USER_ID = ENCRYPTION_STAGE.USER_ID AND
                               -- files correlation between the stages exceeds at 75% match of file between the stages, measure against the 'smaller' stage
                               ARRAY_SIZE(ARRAY_INTERSECTION(COLLECTION_STAGE.INVOLVED_FILES, ENCRYPTION_STAGE.INVOLVED_FILES))
                                   >= IFF(ARRAY_SIZE(COLLECTION_STAGE.INVOLVED_FILES) < ARRAY_SIZE(ENCRYPTION_STAGE.INVOLVED_FILES), ARRAY_SIZE(COLLECTION_STAGE.INVOLVED_FILES) * 0.75,  ARRAY_SIZE(ENCRYPTION_STAGE.INVOLVED_FILES) * 0.75)
