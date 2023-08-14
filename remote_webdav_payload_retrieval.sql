-- The query looks for instances of remote file referencing through WebDav, an artifact that may indicate payload retrieval
-- This activity was observed by the team in a recent InfoStealer campaign targeting Mexico
-- When a file is referenced via WebDav, the Rundll is spawned by svchost.exe (hosting the WebClient service) with the following command line structure:
-- rundll32.exe C:\Windows\system32\davclnt.dll,DavSetCookie <remote_host> http://<remote_host>/<path>/<to>/<payload>
-- The query uses Hunters' EDR Process Creation Unified Scheme and filters out internal IPs
-- It is recommended to add further enrichments and tune the query to identify suspicious characteristics like remote servers rarely accessed by the organization, suspicious file extensions etc.
-- It may be possible to retrieve the file hash and further details from its local copy in the WebDav cache directory at %systemdrive%\windows\ServiceProfiles\LocalService\AppData\Local\Temp\TfsStore
SELECT
    SPLIT_PART(SPLIT_PART(LOWER(TARGET_PROCESS_COMMANDLINE), '//', 2), '/', 1) AS TARGET_SERVER,
    COUNT(DISTINCT AGENT_ID) AS DISTINCT_AIDS,
    COUNT(DISTINCT LOWER(TARGET_PROCESS_COMMANDLINE)) AS DISTINCT_CMDLINES,
    ANY_VALUE(TARGET_PROCESS_COMMANDLINE) AS EXAMPLE_TARGET_PROCESS_COMMANDLINE
FROM INVESTIGATION.EDR_PROCESS_CREATION_EVENTS
WHERE LOWER(TARGET_PROCESS_COMMANDLINE) LIKE '%rundll32.exe %\\windows\\system32\\davclnt.dll,%davsetcookie %'
    AND EVENT_TIME > CURRENT_TIMESTAMP - INTERVAL '30d'
    AND DEVICE_PLATFORM = 'WINDOWS'
    AND TARGET_SERVER LIKE '%.%'                                                     -- Either FQDN or IP
    AND (INITIATING_PROCESS_NAME = 'svchost.exe' OR INITIATING_PROCESS_NAME IS NULL) -- Initiated by svchost
    -- Filter out internal IP ranges
    AND NOT (
        TARGET_SERVER LIKE '10.%'
        OR TARGET_SERVER LIKE '192.168.%'
        OR TARGET_SERVER LIKE '127.%'
        OR TARGET_SERVER REGEXP '^172\\.(1[6-9]|2[0-9]|3[0-1])\\..*' -- 172.16.0.0–172.31.255.255
        OR TARGET_SERVER LIKE '169.254.%'
        OR TARGET_SERVER LIKE '0.%'
        OR TARGET_SERVER REGEXP '^100\\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\\..*' -- 100.64.0.0–100.127.255.255
        OR TARGET_SERVER LIKE '192.0.0.%'
        OR TARGET_SERVER LIKE '192.0.2.%'
        OR TARGET_SERVER LIKE '192.88.99.%'
        OR TARGET_SERVER REGEXP '^198.1[8-9]\\..*'
        OR TARGET_SERVER LIKE '198.51.100.%'
        OR TARGET_SERVER LIKE '203.0.113.%'
        OR TARGET_SERVER LIKE '233.252.0.%'
        OR TARGET_SERVER REGEXP '^(22[4-9]|23[0-9])\\..*'
        OR TARGET_SERVER REGEXP '^(24[0-9]|25[0-5])\\..*'
        OR TARGET_SERVER LIKE 'fc00%'
        OR TARGET_SERVER LIKE 'fe80%'
        OR TARGET_SERVER LIKE 'ff00%'
        OR LOWER(TARGET_SERVER) LIKE 'localhost:%'
        OR LOWER(TARGET_SERVER) = 'localhost'
    )
GROUP BY TARGET_SERVER
ORDER BY TARGET_SERVER ASC;