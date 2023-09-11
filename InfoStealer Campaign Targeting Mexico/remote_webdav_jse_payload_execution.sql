-- This query detects instances of wscript.exe process creations that involve the execution of a .jse (Encoded Jscript) file from a remote WebDav share
-- This activity was observed by the team in a recent InfoStealer campaign targeting Mexico (August 2023)
-- The query uses Hunters' EDR Process Creation Unified Scheme
-- It may be possible to retrieve the file hash and further details from its local copy in the WebDav cache directory at %systemdrive%\windows\ServiceProfiles\LocalService\AppData\Local\Temp\TfsStore
SELECT DISTINCT
    EVENT_TIME,
    AGENT_ID,
    TARGET_PROCESS_COMMANDLINE
FROM INVESTIGATION.EDR_PROCESS_CREATION_EVENTS
WHERE LOWER(TARGET_PROCESS_COMMANDLINE) LIKE '%wscript.exe%\\%@%\\%.jse%'
    AND EVENT_TIME > CURRENT_TIMESTAMP - INTERVAL '30d'
ORDER BY EVENT_TIME ASC;
