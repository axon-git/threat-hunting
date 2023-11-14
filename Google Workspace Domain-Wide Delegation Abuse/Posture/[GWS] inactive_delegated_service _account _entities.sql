-- The query deigned identify inactive delegated service account entities in your GWS environment

-- Guidelines:
-- Review the query results, focusing on service accounts that haven't initiated any API calls in a reasonable time frame, which can be identified by the LAST_API_CALL and DAYS_SINCE_LAST_CALL attributes. We decided to not limit the query to a certain threshold as it should be based on your organization's policy. 
-- Evaluate the inactive delegations outlined in the query results. If they aren't in use, you may want to consider removing them. 
-- Examine the private keys of the found GCP service accounts. If you encounter a key that isn't recognizable, you might want to consider revoking it and generating a new one.
-- If the delegation is determined to be in the expected configuration, despite it not currently being utilized, review the OAuth scopes attached to the service. You might want to consider removing any scopes that are not absolutely needed for the service to function.


WITH GSW_GCP_SA_DELEGATION AS (
    -- creation and deletion of GCP SA delegation config
    SELECT
        ID_TIME,
        EVENT_PARAMETERS:API_CLIENT_NAME::varchar AS OAUTH_CLIENT_ID,
        EVENT_PARAMETERS:DOMAIN_NAME AS DOMAIN_NAME,
        EVENT_PARAMETERS:API_SCOPES AS OAUTH_SCOPES,
        ACTOR_EMAIL,
        IFF(REGEXP_LIKE(EVENT_PARAMETERS:API_CLIENT_NAME, '[[:digit:]]+'), 'SA_TYPE', 'GWS_MARKETPLACE_APP') AS API_TYPE,
        CASE
            WHEN EVENT_NAME = 'REMOVE_API_CLIENT_ACCESS' THEN 'DELETION'
            WHEN EVENT_NAME = 'AUTHORIZE_API_CLIENT_ACCESS' THEN 'CREATION'
            ELSE NULL
        END AS EVENT_ACTION
    FROM RAW.GSUITE_ACTIVITY
    WHERE ID_APPLICATION_NAME = 'admin'
      AND EVENT_NAME IN ('AUTHORIZE_API_CLIENT_ACCESS', 'REMOVE_API_CLIENT_ACCESS')
      AND EVENT_TYPE = 'DOMAIN_SETTINGS'
      AND API_TYPE = 'SA_TYPE'
      AND ID_TIME > CURRENT_TIMESTAMP - INTERVAL '300 days'
),
OAUTH_API_CALLS AS (
    -- counting API calls made by the OAUTH_CLIENT_ID
    SELECT EVENT_PARAMETERS:client_id::varchar AS OAUTH_CLIENT_ID,
           COUNT(*) AS OAUTH_COUNTER,
           MAX(ID_TIME) AS OAUTH_LAST_API_CALL
    FROM RAW.GSUITE_ACTIVITY
    WHERE EVENT_PARAMETERS:client_id IN (SELECT OAUTH_CLIENT_ID FROM GSW_GCP_SA_DELEGATION)
      AND GSUITE_ACTIVITY.ID_TIME > CURRENT_TIMESTAMP - INTERVAL '300 days'
    GROUP BY OAUTH_CLIENT_ID
)
SELECT
    GSW.ID_TIME AS DELEGATION_TIME,
    GSW.OAUTH_CLIENT_ID,
    GSW.ACTOR_EMAIL,
    GSW.DOMAIN_NAME,
    GSW.OAUTH_SCOPES,
    CASE WHEN GSW.EVENT_ACTION = 'DELETION' THEN TRUE ELSE FALSE END AS DELEGEATION_DELETED,
    OAUTH.OAUTH_COUNTER AS OAUTH_API_COUNTER,
    OAUTH.OAUTH_LAST_API_CALL AS OAUTH_LAST_API_CALL,
    datediff(day, OAUTH.OAUTH_LAST_API_CALL, current_timestamp()::timestamp)  as OAUTH_DAYS_SINCE_LAST_CALL
FROM GSW_GCP_SA_DELEGATION GSW
LEFT JOIN OAUTH_API_CALLS OAUTH ON OAUTH.OAUTH_CLIENT_ID = GSW.OAUTH_CLIENT_ID
WHERE DELEGEATION_DELETED = FALSE
QUALIFY ROW_NUMBER() OVER ( PARTITION BY GSW.OAUTH_CLIENT_ID ORDER BY DELEGATION_TIME DESC ) = 1
