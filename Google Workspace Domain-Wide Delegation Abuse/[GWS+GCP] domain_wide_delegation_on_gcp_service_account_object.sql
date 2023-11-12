-- The thesis looks for the AUTHORIZE_API_CLIENT_ACCESS event in GSW admin logs and focuses on GCP service accounts by identifying the object as an integer. Given the fact the AUTHORIZE_API_CLIENT_ACCESS event in GSW doesn't contain details on the service account rather than the OAuth client ID, the thesis performs a cross-correlation with the related GCP audit events to gather information on the relevant SA keys

WITH SA_KEY_CREATION AS (
    -- Creation of GCP private keys for Service Account Resources
    SELECT
       EVENT_TIME           KEY_CREATION_TIME,
       PROJECT_ID           GCP_PROJECT_ID,
       PRINCIPAL_EMAIL      GCP_CALLER_EMAIL,
       CALLER_IP            SA_CREATION_CALLER_IP,
       CALLER_USER_AGENT    SA_CREATION_USER_AGENT,
       -- the OAuth client ID representation
       RESOURCE:labels:unique_id OAUTH_CLIENT_ID,
       SPLIT_PART(method_name, '.', -1) STRIP_METHOD_NAME,
       -- the SA's expiration date, by default unlimited (9999-12-31 23:59:59)
       TO_TIMESTAMP_NTZ(PROTO_PAYLOAD:response:valid_before_time:seconds::integer)  as SA_EXPIRATION_DATE,
        -- the private key format, by default is GOOGLE_CREDENTIALS_FILE (Google's SA json)
        CASE WHEN  PROTO_PAYLOAD:request:private_key_type  = 0 THEN 'UNSPECIFIED'
             WHEN  PROTO_PAYLOAD:request:private_key_type  = 1 THEN 'PKCS12_FILE'
             WHEN PROTO_PAYLOAD:request:private_key_type  = 2  THEN 'GOOGLE_CREDENTIALS_FILE'
             END                                                                as SA_PRIVATE_KEY_TYPE,
        -- the
        CASE WHEN PROTO_PAYLOAD:response:key_type = 0 THEN 'KEY_TYPE_UNSPECIFIED'
             WHEN PROTO_PAYLOAD:response:key_type = 1 THEN 'USER_MANAGED'
             WHEN PROTO_PAYLOAD:response:key_type = 2 THEN 'SYSTEM_MANAGED'
             END                                                                as SA_KEY_MANGMANET_CONFIG,
        CASE WHEN PROTO_PAYLOAD:response:key_origin = 0 THEN 'ORIGIN_UNSPECIFIED'
             WHEN PROTO_PAYLOAD:response:key_origin = 1 THEN 'USER_PROVIDED'
             WHEN PROTO_PAYLOAD:response:key_origin = 2 THEN 'GOOGLE_PROVIDED'
             END                                                                as SA_KEY_ORIGIN,
       IFF( row_number() over (partition by OAUTH_CLIENT_ID order by EVENT_TIME ASC) > 1, 'new_key_for_existing_sa','first_key_for_sa')     SA_KEY_STATE,
       IFF( IP is not null, 'TRUE', 'FALSE')   as KNOWN_ORGANIZATION_IP
  FROM RAW.GCP_AUDIT
 LEFT JOIN (
  SELECT DISTINCT IP FROM INVESTIGATION.ORGANIZATIONAL_IP WHERE SPECIFIC_SOURCE_TYPE='endpoint_ip_mapping'
           ) ON CALLER_IP = IP
 WHERE SERVICE_NAME='iam.googleapis.com'
   AND STRIP_METHOD_NAME='CreateServiceAccountKey'
   AND EVENT_TIME > current_timestamp - interval '90d'
)

SELECT ID_TIME      DELEGATION_TIME,
       ACTOR_EMAIL,
       EVENT_NAME,
       -- the unique identifier for the delegated identity object (eithier GSW app or GCP service account)
       EVENT_PARAMETERS:API_CLIENT_NAME::varchar IDENTITY_OBJECT_GSW,
       -- GCP service accounts are identity object are consist from 21 integer (OAuth client ID)
       IFF(REGEXP_LIKE(EVENT_PARAMETERS:API_CLIENT_NAME, '[[:digit:]]+'), 'SA_TYPE', 'GWS_MARKETPLACE_APP')  API_TYPE,
       EVENT_PARAMETERS:API_SCOPES,
       EVENT_PARAMETERS:DOMAIN_NAME,
       -- SA key creation details (from SA_KEY_CREATION)
       KEY_CREATION_TIME,
       -- GCP email member who created the gcp private key
       GCP_CALLER_EMAIL,
       -- the IP used to create the gcp private key
       SA_CREATION_CALLER_IP,
       -- flag for known organization IP addresses
       KNOWN_ORGANIZATION_IP,
       -- the UA used to create the gcp private key
       SA_CREATION_USER_AGENT,
       -- flag to check whether it is the first time a key created for the service account resource (limitation: the time interval in SA_KEY_CREATION table)
       SA_KEY_STATE,
       -- the GCP project resource attached to the service account
       GCP_PROJECT_ID,
       -- day difference between delegation config and creation of the GCP service account key
       datediff(day, KEY_CREATION_TIME,DELEGATION_TIME)  as DAY_DIFF_BTW_DT_KC
  FROM RAW.GSUITE_ACTIVITY
  LEFT JOIN SA_KEY_CREATION ON SA_KEY_CREATION.OAUTH_CLIENT_ID = IDENTITY_OBJECT_GSW
 WHERE ID_APPLICATION_NAME='admin'
   -- AUTHORIZE_API_CLIENT_ACCESS represent a global delegation for GSW, either for GCP service accounts or global GSW marketplace applications
   AND EVENT_NAME = 'AUTHORIZE_API_CLIENT_ACCESS'
   AND EVENT_TYPE= 'DOMAIN_SETTINGS'
   AND API_TYPE='SA_TYPE'
   AND GSUITE_ACTIVITY.ID_TIME > CURRENT_TIMESTAMP - INTERVAL '90 days'
