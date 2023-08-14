-- The query searches for a UAC bypass method that changes the value of HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin to 0 (=Elevate without prompting)
-- This activity was observed by the team in a recent InfoStealer campaign targeting Mexico
-- The query can be adjusted to the preferred EDR solution
SELECT DISTINCT 
    EVENT_TIME,
    AID,
    EVENT_NAME,
    REGISTRY_KEY,
    REGISTRY_VALUE_NAME,
    REGISTRY_STR_VALUE_DATA,
    REGISTRY_INT_VALUE_DATA,
    REGISTRY_OPERATION_TYPE
FROM EDR_RAW_DATA
WHERE EVENT_TIME > CURRENT_TIMESTAMP - INTERVAL '30d'
    AND LOWER(EVENT_NAME) LIKE '%reg%update%' -- Modify with the relevant EDR event name
    AND REGISTRY_KEY ILIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
    AND REGISTRY_VALUE_NAME = 'ConsentPromptBehaviorAdmin'
    AND REGISTRY_OPERATION_TYPE = '1' -- REG_SET_VALUE
    AND REGISTRY_INT_VALUE_DATA = 0   -- Elevate without prompting
ORDER BY EVENT_TIME ASC;