#pragma once
#include <iads.h>
#include <comutil.h>
#include <atlbase.h>
#include <adshlp.h>
#include <string>
#include <iostream>
#include <string>
#include <map>
#include <AccCtrl.h>
#include <AclAPI.h>
#include <comdef.h>
#include <wincred.h>
#include <codecvt>
#include "utils.h"

#define ABANDON_REPLICATION L"{ee914b82-0a98-11d1-adbb-00c04fd8d5cd}"
#define ADD_GUID L"{440820ad-65b4-11d1-a3da-0000f875ae0d}"
#define ALLOCATE_RIDS L"{1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd}"
#define ALLOWED_TO_AUTHENTICATE L"{68b1d179-0d15-4d4f-ab71-46152e79a7bc}"
#define APPLY_GROUP_POLICY L"{edacfd8f-ffb3-11d1-b41d-00a0c968f939}"
#define CERTIFICATE_ENROLLMENT L"{0e10c968-78fb-11d2-90d4-00c04f79dc55}"
#define CHANGE_DOMAIN_MASTER L"{014bf69c-7b3b-11d1-85f6-08002be74fab}"
#define CHANGE_INFRASTRUCTURE_MASTER L"{cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd}"
#define CHANGE_PDC L"{bae50096-4752-11d1-9052-00c04fc2d4cf}"
#define CHANGE_RID_MASTER L"{d58d5f36-0a98-11d1-adbb-00c04fd8d5cd}"
#define CHANGE_SCHEMA_MASTER L"{e12b56b6-0a95-11d1-adbb-00c04fd8d5cd}"
#define CREATE_INBOUND_FOREST_TRUST L"{e2a36dc9-ae17-47c3-b58b-be34c55ba633}"
#define DO_GARBAGE_COLLECTION L"{fec364e0-0a98-11d1-adbb-00c04fd8d5cd}"
#define DOMAIN_ADMINISTER_SERVER L"{ab721a52-1e2f-11d0-9819-00aa0040529b}"
#define DS_CHECK_STALE_PHANTOMS L"{69ae6200-7f46-11d2-b9ad-00c04f79f805}"
#define DS_CLONE_DOMAIN_CONTROLLER L"{3e0f7e18-2c7a-4c10-ba82-4d926db99a3e}"
#define DS_EXECUTE_INTENTIONS_SCRIPT L"{2f16c4a5-b98e-432c-952a-cb388ba33f2e}"
#define DS_INSTALL_REPLICA L"{9923a32a-3607-11d2-b9be-0000f87a36b2}"
#define DS_QUERY_SELF_QUOTA L"{4ecc03fe-ffc0-4947-b630-eb672a8a9dbc}"
#define DS_REPLICATION_GET_CHANGES L"{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"
#define DS_REPLICATION_GET_CHANGES_ALL L"{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"
#define DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET L"{89e95b76-444d-4c62-991a-0facbeda640c}"
#define DS_REPLICATION_MANAGE_TOPOLOGY L"{1131f6ac-9c07-11d1-f79f-00c04fc2dcd2}"
#define DS_REPLICATION_MONITOR_TOPOLOGY L"{f98340fb-7c5b-4cdb-a00b-2ebdfa115a96}"
#define DS_REPLICATION_SYNCHRONIZE L"{1131f6ab-9c07-11d1-f79f-00c04fc2dcd2}"
#define ENABLE_PER_USER_REVERSIBLY_ENCRYPTED_PASSWORD L"{05c74c5e-4deb-43b4-bd9f-86664c2a7fd5}"
#define GENERATE_RSOP_LOGGING L"{b7b1b3de-ab09-4242-9e30-9980e5d322f7}"
#define GENERATE_RSOP_PLANNING L"{b7b1b3dd-ab09-4242-9e30-9980e5d322f7}"
#define MANAGE_OPTIONAL_FEATURES L"{7c0e2a7c-a419-48e4-a995-10180aad54dd}"
#define MIGRATE_SID_HISTORY L"{ba33815a-4f93-4c76-87f3-57574bff8109}"
#define MSMQ_OPEN_CONNECTOR L"{b4e60130-df3f-11d1-9c86-006008764d0e}"
#define MSMQ_PEEK L"{06bd3201-df3e-11d1-9c86-006008764d0e}"
#define MSMQ_PEEK_COMPUTER_JOURNAL L"{4b6e08c3-df3c-11d1-9c86-006008764d0e}"
#define MSMQ_PEEK_DEAD_LETTER L"{4b6e08c1-df3c-11d1-9c86-006008764d0e}"
#define MSMQ_RECEIVE L"{06bd3200-df3e-11d1-9c86-006008764d0e}"
#define MSMQ_RECEIVE_COMPUTER_JOURNAL L"{4b6e08c2-df3c-11d1-9c86-006008764d0e}"
#define MSMQ_RECEIVE_DEAD_LETTER L"{4b6e08c0-df3c-11d1-9c86-006008764d0e}"
#define MSMQ_RECEIVE_JOURNAL L"{06bd3203-df3e-11d1-9c86-006008764d0e}"
#define MSMQ_SEND L"{06bd3202-df3e-11d1-9c86-006008764d0e}"
#define OPEN_ADDRESS_BOOK L"{a1990816-4298-11d1-ade2-00c04fd8d5cd}"
#define READ_ONLY_REPLICATION_SECRET_SYNCHRONIZATION L"{1131f6ae-9c07-11d1-f79f-00c04fc2dcd2}"
#define REANIMATE_TOMBSTONES L"{45ec5156-db7e-47bb-b53f-dbeb2d03c40f}"
#define RECALCULATE_HIERARCHY L"{0bc1554e-0a99-11d1-adbb-00c04fd8d5cd}"
#define RECALCULATE_SECURITY_INHERITANCE L"{62dd28a8-7f46-11d2-b9ad-00c04f79f805}"
#define RECEIVE_AS L"{ab721a56-1e2f-11d0-9819-00aa0040529b}"
#define REFRESH_GROUP_CACHE L"{9432c620-033c-4db7-8b58-14ef6d0bf477}"
#define RELOAD_SSL_CERTIFICATE L"{1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8}"
#define RUN_PROTECT_ADMIN_GROUPS_TASK L"{7726b9d5-a4b4-4288-a6b2-dce952e80a7f}"
#define SAM_ENUMERATE_ENTIRE_DOMAIN L"{91d67418-0135-4acc-8d79-c08e857cfbec}"
#define SEND_AS L"{ab721a54-1e2f-11d0-9819-00aa0040529b}"
#define SEND_TO L"{ab721a55-1e2f-11d0-9819-00aa0040529b}"
#define UNEXPIRE_PASSWORD L"{ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501}"
#define UPDATE_PASSWORD_NOT_REQUIRED_BIT L"{280f369c-67c7-438e-ae98-1d46f3c6f541}"
#define UPDATE_SCHEMA_CACHE L"{be2bb760-7f46-11d2-b9ad-00c04f79f805}"
#define USER_CHANGE_PASSWORD L"{ab721a53-1e2f-11d0-9819-00aa0040529b}"
#define USER_FORCE_CHANGE_PASSWORD L"{00299570-246d-11d0-a768-00aa006e0529}"



typedef struct ADOptions {
    std::string sActiveDirectoryExtendedRight = "";
    std::string sActiveDirectoryUser = "";
    std::string sLdapPath = "";
    bool isActiveDirectoryAddRight = false;
    bool isActiveDirectoryRemoveRight = false;
    bool isListActiveDirectoryExtendedRights = false;
    std::string sActiveDirectoryRight = "";
    bool isActiveDirectoryRights = false;
    bool isListActiveDirectoryRights = false;
    std::string logonUser = "";
};


HRESULT ADSetRight(
    IADs* pObject,
    long lAccessMask,
    long lAccessType,
    long lAccessInheritFlags,
    LPOLESTR szObjectGUID,
    LPOLESTR szInheritedObjectGUID,
    LPOLESTR szTrustee,
    BOOL bAddOrRemove
);

HRESULT ADSetExtendedRight(IADs* pObject,
    LPWSTR pwszRightsGUID,
    LONG lAccessType,
    LONG fInheritanceFlags,
    LONG fAppliesToObjectType,
    LPWSTR pwszTrustee,
    BOOL bAddOrRemove
);

VOID ActiveDirectoryExtendRightsCallBack(ADOptions* Options);

VOID ActiveDirectoryRightsCallBack(ADOptions* Options);