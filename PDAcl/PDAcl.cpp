﻿// PDAcl.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iads.h>
#include <comutil.h>
#include <atlbase.h>
#include <adshlp.h>
#include <string>
#include <iostream>
#include <string>
#include <codecvt>
#include <map>
#include <AccCtrl.h>
#include <AclAPI.h>
#include <comdef.h>
#include <wincred.h>
#include "ADExtendedRight.h"
#include "CLI11.hpp"

#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "Adsiid.lib")
#pragma comment(lib, "Activeds.lib")

std::map<std::string, INT> ADRightsMap{
    {"ADS-Right-Delete", ADS_RIGHT_DELETE},
    {"ADS-Right-Red-Control",ADS_RIGHT_READ_CONTROL},
    {"ADS-Right-Write-DAC",ADS_RIGHT_WRITE_DAC},
    {"ADS-Right-Write-Owner",ADS_RIGHT_WRITE_OWNER},
    {"ADS-Right-Synchronize", ADS_RIGHT_SYNCHRONIZE},
    {"ADS-Right-Access-System-Security",ADS_RIGHT_ACCESS_SYSTEM_SECURITY},
    {"ADS-Right-Generic-Read",ADS_RIGHT_GENERIC_READ},
    {"ADS-Right-Generic-Write",ADS_RIGHT_GENERIC_WRITE},
    {"ADS-Right-Generic-Execute",ADS_RIGHT_GENERIC_EXECUTE},
    {"ADS-Right-Generic-All", ADS_RIGHT_GENERIC_ALL},
    {"ADS-Right-Ds-Create-Child", ADS_RIGHT_DS_CREATE_CHILD},
    {"ADS-Right-Ds-Delete-Child", ADS_RIGHT_DS_DELETE_CHILD},
    {"ADS-Right-Actrl-Ds-List", ADS_RIGHT_ACTRL_DS_LIST},
    {"ADS-Right-Ds-Self", ADS_RIGHT_DS_SELF},
    {"ADS-Right-Ds-Read-Prop", ADS_RIGHT_DS_READ_PROP},
    {"ADS-Right-Ds-Write-Prop", ADS_RIGHT_DS_WRITE_PROP},
    {"ADS-Right-Ds-Delete-Tree", ADS_RIGHT_DS_DELETE_TREE},
    {"ADS-Right-Ds-List-Object", ADS_RIGHT_DS_LIST_OBJECT},
    {"ADS-Right-Ds-Control-Access", ADS_RIGHT_DS_CONTROL_ACCESS}
};

std::map<std::string, std::wstring> ADExtendedRightsMap{
    {"Abandon-Replication", ABANDON_REPLICATION},
    {"Add-GUID",ADD_GUID},
    {"Allocate-Rids",ALLOCATE_RIDS},
    {"Allowed-To-Authenticate",ALLOWED_TO_AUTHENTICATE},
    {"Apply-Group-Policy",APPLY_GROUP_POLICY},
    {"Certificate-Enrollment",CERTIFICATE_ENROLLMENT},
    {"Change-Domain-Master",CHANGE_DOMAIN_MASTER},
    {"Change-Infrastructure-Master",CHANGE_INFRASTRUCTURE_MASTER},
    {"Change-PDC",CHANGE_PDC},
    {"Change-Rid-Master",CHANGE_RID_MASTER},
    {"Change-Schema-Master",CHANGE_SCHEMA_MASTER},
    {"Create-Inbound-Forest-Trust",CREATE_INBOUND_FOREST_TRUST},
    {"Do-Garbage-Collection",DO_GARBAGE_COLLECTION},
    {"Domain-Administer-Server",DOMAIN_ADMINISTER_SERVER},
    {"DS-Check-Stale-Phantoms",DS_CHECK_STALE_PHANTOMS},
    {"DS-Clone-Domain-Controller",DS_CLONE_DOMAIN_CONTROLLER},
    {"DS-Execute-Intentions-Script",DS_EXECUTE_INTENTIONS_SCRIPT},
    {"DS-Install-Replica",DS_INSTALL_REPLICA},
    {"DS-Query-Self-Quota",DS_QUERY_SELF_QUOTA},
    {"DS-Replication-Get-Changes",DS_REPLICATION_GET_CHANGES},
    {"DS-Replication-Get-Changes-All",DS_REPLICATION_GET_CHANGES_ALL},
    {"DS-Replication-Get-Changes-In-Filtered-Set",DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET},
    {"DS-Replication-Manage-Topology",DS_REPLICATION_MANAGE_TOPOLOGY},
    {"DS-Replication-Monitor-Topology",DS_REPLICATION_MONITOR_TOPOLOGY},
    {"DS-Replication-Synchronize",DS_REPLICATION_SYNCHRONIZE},
    {"Enable-Per-User-Reversibly-Encrypted-Password",ENABLE_PER_USER_REVERSIBLY_ENCRYPTED_PASSWORD},
    {"Generate-RSoP-Logging",GENERATE_RSOP_LOGGING},
    {"Generate-RSoP-Planning",GENERATE_RSOP_PLANNING},
    {"Manage-Optional-Features",MANAGE_OPTIONAL_FEATURES},
    {"Migrate-SID-History",MIGRATE_SID_HISTORY},
    {"msmq-Open-Connector",MSMQ_OPEN_CONNECTOR},
    {"msmq-Peek",MSMQ_PEEK},
    {"msmq-Peek-computer-Journal",MSMQ_PEEK_COMPUTER_JOURNAL},
    {"msmq-Peek-Dead-Letter",MSMQ_PEEK_DEAD_LETTER},
    {"msmq-Receive",MSMQ_RECEIVE},
    {"msmq-Receive-computer-Journal",MSMQ_RECEIVE_COMPUTER_JOURNAL},
    {"msmq-Receive-Dead-Letter",MSMQ_RECEIVE_DEAD_LETTER},
    {"msmq-Receive-journal",MSMQ_RECEIVE_JOURNAL},
    {"msmq-Send",MSMQ_SEND},
    {"Open-Address-Book",OPEN_ADDRESS_BOOK},
    {"Read-Only-Replication-Secret-Synchronization",READ_ONLY_REPLICATION_SECRET_SYNCHRONIZATION},
    {"Reanimate-Tombstones",REANIMATE_TOMBSTONES},
    {"Recalculate-Hierarchy",RECALCULATE_HIERARCHY},
    {"Recalculate-Security-Inheritance",RECALCULATE_SECURITY_INHERITANCE},
    {"Receive-As",RECEIVE_AS},
    {"Refresh-Group-Cache",REFRESH_GROUP_CACHE},
    {"Reload-SSL-Certificate",RELOAD_SSL_CERTIFICATE},
    {"Run-Protect-Admin-Groups-Task",RUN_PROTECT_ADMIN_GROUPS_TASK},
    {"SAM-Enumerate-Entire-Domain",SAM_ENUMERATE_ENTIRE_DOMAIN},
    {"Send-As",SEND_AS},
    {"Send-To",SEND_TO},
    {"Unexpire-Password",UNEXPIRE_PASSWORD},
    {"Update-Password-Not-Required-Bit",UPDATE_PASSWORD_NOT_REQUIRED_BIT},
    {"Update-Schema-Cache",UPDATE_SCHEMA_CACHE},
    {"User-Change-Password",USER_CHANGE_PASSWORD},
    {"User-Force-Change-Password",USER_FORCE_CHANGE_PASSWORD}

};

std::map<std::string, INT> ServiceRightsMap{
    {"Service-All-Access", SERVICE_ALL_ACCESS},
    {"Service-Change-Config", SERVICE_CHANGE_CONFIG},
    {"Service-Enumerate-Dependents", SERVICE_ENUMERATE_DEPENDENTS},
    {"Service-Interrogate", SERVICE_INTERROGATE},
    {"Service-Pause-Continue", SERVICE_PAUSE_CONTINUE},
    {"Service-Query-Config", SERVICE_QUERY_CONFIG},
    {"Service-Query-Status", SERVICE_QUERY_STATUS},
    {"Service-Start", SERVICE_START},
    {"Service-Stop", SERVICE_STOP},
    {"Service-User-Defined-Control", SERVICE_USER_DEFINED_CONTROL},
    {"Access-System-Security", ACCESS_SYSTEM_SECURITY},
    {"Delete", DELETE},
    {"Read-Control", READ_CONTROL},
    {"Write-Dac", WRITE_DAC},
    {"Write-Owner", WRITE_OWNER},
    {"Generic-Read", GENERIC_READ},
    {"Generic-Write", GENERIC_WRITE},
    {"Generic-Execute", GENERIC_EXECUTE},
};



HRESULT ADSetExtendedRight(IADs* pObject,
    LPWSTR pwszRightsGUID,
    LONG lAccessType,
    LONG fInheritanceFlags,
    LONG fAppliesToObjectType,
    LPWSTR pwszTrustee,
    BOOL bAddOrRemove
    )

{
    if (!pObject || !pwszRightsGUID || !pwszTrustee)
    {
        return E_INVALIDARG;
    }

    if ((lAccessType != ADS_ACETYPE_ACCESS_ALLOWED_OBJECT) &&
        (lAccessType != ADS_ACETYPE_ACCESS_DENIED_OBJECT))
    {
        return E_INVALIDARG;
    }

    HRESULT hr;

    // Get the nTSecurityDescriptor attribute.
    CComBSTR sbstrNTSecDesc = L"nTSecurityDescriptor";
    CComVariant svarSecDesc;
    hr = pObject->Get(sbstrNTSecDesc, &svarSecDesc);
    if (FAILED(hr))
    {
        return hr;
    }

    /*
    The type should be VT_DISPATCH which is an IDispatch pointer to the
    security descriptor object.
    */
    if (VT_DISPATCH != svarSecDesc.vt)
    {
        return E_FAIL;
    }

    // Get the IADsSecurityDescriptor interface from the IDispatch pointer.
    CComPtr<IADsSecurityDescriptor> spSecDesc;
    hr = svarSecDesc.pdispVal->QueryInterface(IID_IADsSecurityDescriptor, (void**)&spSecDesc);
    if (FAILED(hr))
    {
        return hr;
    }

    // Get the DACL object.
    CComPtr<IDispatch> spDispDACL;
    hr = spSecDesc->get_DiscretionaryAcl(&spDispDACL);
    if (FAILED(hr))
    {
        return hr;
    }

    // Get the IADsAccessControlList interface from the DACL object.
    CComPtr<IADsAccessControlList> spACL;
    hr = spDispDACL->QueryInterface(IID_IADsAccessControlList, (void**)&spACL);
    if (FAILED(hr))
    {
        return hr;
    }
    
    // Create the COM object for the new ACE.
    CComPtr<IADsAccessControlEntry> spACE;
    hr = CoCreateInstance(CLSID_AccessControlEntry,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_IADsAccessControlEntry,
        (void**)&spACE);
    if (FAILED(hr))
    {
        return hr;
    }
    
    // Set the properties of the new ACE.

    /*
    For an extended control access right, set the mask to
    ADS_RIGHT_DS_CONTROL_ACCESS.
    */
    hr = spACE->put_AccessMask(ADS_RIGHT_DS_CONTROL_ACCESS);
    if (FAILED(hr))
    {
        return hr;
    }

    // Set the trustee.
    hr = spACE->put_Trustee(pwszTrustee);
    if (FAILED(hr))
    {
        return hr;
    }

    /*
    For extended control access rights, set AceType to
    ADS_ACETYPE_ACCESS_ALLOWED_OBJECT or ADS_ACETYPE_ACCESS_DENIED_OBJECT.
    */
    hr = spACE->put_AceType(lAccessType);
    if (FAILED(hr))
    {
        return hr;
    }

    /*
    For this example, set the AceFlags so that ACE is not inherited by child
    objects.
    */
    hr = spACE->put_AceFlags(fInheritanceFlags);
    if (FAILED(hr))
    {
        return hr;
    }

    /*
    Flags specifies whether the ACE applies to the current object, child objects,
    or both. For this example, fAppliesToInheritedObject is set to
    ADS_FLAG_OBJECT_TYPE_PRESENT so that the right applies only to the current
    object.
    */
    hr = spACE->put_Flags(fAppliesToObjectType);
    if (FAILED(hr))
    {
        return hr;
    }

    /*
    For extended control access rights, set ObjectType to the rightsGUID of the
    extended right.
    */
    if (fAppliesToObjectType & ADS_FLAG_OBJECT_TYPE_PRESENT)
    {
        hr = spACE->put_ObjectType(pwszRightsGUID);
        if (FAILED(hr))
        {
            return hr;
        }
    }

    // Set the inherited object type if right applies to child objects.
    if (fAppliesToObjectType & ADS_FLAG_INHERITED_OBJECT_TYPE_PRESENT)
    {
        hr = spACE->put_InheritedObjectType(pwszRightsGUID);
        if (FAILED(hr))
        {
            return hr;
        }
    }

    // Get the IDispatch pointer for the ACE.
    CComPtr<IDispatch> spDispACE;
    hr = spACE->QueryInterface(IID_IDispatch, (void**)&spDispACE);
    if (FAILED(hr))
    {
        return hr;
    }

    if (bAddOrRemove) {
        // Add the ACE to the ACL.
        std::cout << "[*] Add the ACE to the ACL." << std::endl;
        hr = spACL->AddAce(spDispACE);
    }
    else {
        // Remove the ACE to the ACL.
        std::cout << "[*] Remove the ACE to the ACL." << std::endl;
        hr = spACL->RemoveAce(spDispACE);
    }

    if (FAILED(hr))
    {
        return hr;
    }

    // Update the DACL property.
    hr = spSecDesc->put_DiscretionaryAcl(spDispDACL);
    if (FAILED(hr))
    {
        return hr;
    }

    /*
    Write the updated value for the ntSecurityDescriptor attribute to the
    property cache.
    */
    hr = pObject->Put(sbstrNTSecDesc, svarSecDesc);
    if (FAILED(hr))
    {
        return hr;
    }

    // Call SetInfo to update the property on the object in the directory.
    hr = pObject->SetInfo();

    return hr;
}


HRESULT ADSetRight(
    IADs* pObject,
    long lAccessMask,
    long lAccessType,
    long lAccessInheritFlags,
    LPOLESTR szObjectGUID,
    LPOLESTR szInheritedObjectGUID,
    LPOLESTR szTrustee,
    BOOL bAddOrRemove
)
{
    VARIANT varSD;
    HRESULT hr = E_FAIL;
    IADsAccessControlList* pACL = NULL;
    IADsSecurityDescriptor* pSD = NULL;
    IDispatch* pDispDACL = NULL;
    IADsAccessControlEntry* pACE = NULL;
    IDispatch* pDispACE = NULL;
    long lFlags = 0L;

    // The following code example takes the szTrustee in an expected naming format 
    // and assumes it is the name for the correct trustee.
    // The application should validate the specified trustee.
    if (!szTrustee || !pObject)
        return E_INVALIDARG;

    VariantInit(&varSD);

    // Get the nTSecurityDescriptor.
    // Type should be VT_DISPATCH - an IDispatch pointer to the security descriptor object.
    hr = pObject->Get(_bstr_t("nTSecurityDescriptor"), &varSD);
    if (FAILED(hr) || varSD.vt != VT_DISPATCH) {
        wprintf(L"get nTSecurityDescriptor failed: 0x%x\n", hr);
        return hr;
    }

    hr = V_DISPATCH(&varSD)->QueryInterface(IID_IADsSecurityDescriptor, (void**)&pSD);
    if (FAILED(hr)) {
        wprintf(L"QueryInterface for IADsSecurityDescriptor failed: 0x%x\n", hr);
        goto cleanup;
    }

    // Get the DACL.
    hr = pSD->get_DiscretionaryAcl(&pDispDACL);
    if (SUCCEEDED(hr))
        hr = pDispDACL->QueryInterface(IID_IADsAccessControlList, (void**)&pACL);
    if (FAILED(hr)) {
        wprintf(L"Could not get DACL: 0x%x\n", hr);
        goto cleanup;
    }

    // Create the COM object for the new ACE.
    hr = CoCreateInstance(
        CLSID_AccessControlEntry,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_IADsAccessControlEntry,
        (void**)&pACE
    );
    if (FAILED(hr)) {
        wprintf(L"Could not create ACE object: 0x%x\n", hr);
        goto cleanup;
    }

    // Set the properties for the new ACE.

    // Set the mask that specifies the access right.
    hr = pACE->put_AccessMask(lAccessMask);

    // Set the trustee.
    hr = pACE->put_Trustee(szTrustee);

    // Set AceType.
    hr = pACE->put_AceType(lAccessType);

    // Set AceFlags to specify whether other objects can inherit the ACE from the specified object.
    hr = pACE->put_AceFlags(lAccessInheritFlags);

    // If an szObjectGUID is specified, add ADS_FLAG_OBJECT_TYPE_PRESENT 
    // to the lFlags mask and set the ObjectType.
    if (szObjectGUID)
    {
        lFlags |= ADS_FLAG_OBJECT_TYPE_PRESENT;
        hr = pACE->put_ObjectType(szObjectGUID);
    }

    // If an szInheritedObjectGUID is specified, add ADS_FLAG_INHERITED_OBJECT_TYPE_PRESENT 
    // to the lFlags mask and set the InheritedObjectType.
    if (szInheritedObjectGUID)
    {
        lFlags |= ADS_FLAG_INHERITED_OBJECT_TYPE_PRESENT;
        hr = pACE->put_InheritedObjectType(szInheritedObjectGUID);
    }

    // Set flags if ObjectType or InheritedObjectType were set.
    if (lFlags)
        hr = pACE->put_Flags(lFlags);

    // Add the ACE to the ACL to the SD to the cache to the object.
    // Call the QueryInterface method for the IDispatch pointer to pass to the AddAce method.
    hr = pACE->QueryInterface(IID_IDispatch, (void**)&pDispACE);
    if (SUCCEEDED(hr))
    {
        // Set the ACL revision.
        hr = pACL->put_AclRevision(ACL_REVISION_DS);

        if (bAddOrRemove) {
            // Add the ACE.
            hr = pACL->AddAce(pDispACE);
        }
        else {
            // Remove the ACE.
            // std::cout << "[*] Remove the ACE ..." << std::endl;
            hr = pACL->RemoveAce(pDispACE);
            
        }
        
        if (SUCCEEDED(hr))
        {
            // Write the DACL.
            hr = pSD->put_DiscretionaryAcl(pDispDACL);
            
            if (SUCCEEDED(hr))
            {
                // Write the ntSecurityDescriptor property to the property cache.
                hr = pObject->Put(CComBSTR("nTSecurityDescriptor"), varSD);
                if (SUCCEEDED(hr))
                {
                    //std::cout << "[*] Call SetInfo to update the property on the object in the directory." << std::endl;
                    hr = pObject->SetInfo();
                    
                }
            }
        }
    }

cleanup:
    if (pDispACE)
        pDispACE->Release();
    if (pACE)
        pACE->Release();
    if (pACL)
        pACL->Release();
    if (pDispDACL)
        pDispDACL->Release();
    if (pSD)
        pSD->Release();

    VariantClear(&varSD);
    return hr;
}


BOOL ModifyServiceACL(LPTSTR ServiceName, LPTSTR Username, DWORD dwGrantAccess, BOOL isAdd = FALSE) {
    SC_HANDLE hService = NULL;
    SC_HANDLE schSCManager = NULL;
    PSECURITY_DESCRIPTOR psd = NULL;
    PACL                 pacl = NULL;
    PACL                 pNewAcl = NULL;
    BOOL                 bDaclPresent = FALSE;
    BOOL                 bDaclDefaulted = FALSE;
    DWORD                dwError = 0;
    DWORD                dwSize = 0;
    DWORD                dwBytesNeeded = 0;
    //ACCESS_ALLOWED_ACE* ACE;
    EXPLICIT_ACCESS      ea = { 0 };
    SECURITY_DESCRIPTOR  sd = { 0 };
    DWORD dwServiceAccess = WRITE_DAC | READ_CONTROL;

    schSCManager = OpenSCManager(NULL, NULL, dwServiceAccess);

    if (schSCManager == NULL) {
        fprintf(stderr, "[!] OpenSCManager Error : %d\n", GetLastError());
        return FALSE;
    }

    hService = OpenService(schSCManager, ServiceName, dwServiceAccess);
    if (hService == NULL) {
        fprintf(stderr, "[!] OpenService Error : %d\n", GetLastError());
        return FALSE;
    }

    if (!QueryServiceObjectSecurity(hService,
        DACL_SECURITY_INFORMATION,
        &psd,           // using NULL does not work on all versions
        0,
        &dwBytesNeeded))
    {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            dwSize = dwBytesNeeded;
            psd = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(),
                HEAP_ZERO_MEMORY, dwSize);
            if (psd == NULL)
            {
                // Note: HeapAlloc does not support GetLastError.
                fprintf(stderr, "[-] HeapAlloc failed\n");
                return FALSE;
            }

            if (!QueryServiceObjectSecurity(hService,
                DACL_SECURITY_INFORMATION, psd, dwSize, &dwBytesNeeded))
            {
                fprintf(stderr, "[*] QueryServiceObjectSecurity failed (%d)\n", GetLastError());
                return FALSE;
            }
        }
        else
        {
            fprintf(stderr, "[*] QueryServiceObjectSecurity failed (%d)\n", GetLastError());
            return FALSE;
        }
    }
    if (!GetSecurityDescriptorDacl(psd, &bDaclPresent, &pacl,
        &bDaclDefaulted))
    {
        fprintf(stderr, "[*] GetSecurityDescriptorDacl failed(%d)\n", GetLastError());
        return FALSE;
    }

    GetSecurityDescriptorDacl(psd, &bDaclPresent, &pacl, &bDaclDefaulted);

    if (IsValidAcl(pacl) == FALSE) {
        DWORD dwError = GetLastError();
        fprintf(stderr, "[!] Error - %d GetSecurityInfo\n", dwError);
        return FALSE;
    }
    fprintf(stderr, "[+] ACL Count : %d \n", pacl->AceCount);

    if (isAdd == FALSE) {
        BuildExplicitAccessWithName(&ea, Username,
            dwGrantAccess,
            REVOKE_ACCESS, CONTAINER_INHERIT_ACE);
        ea.grfAccessMode = REVOKE_ACCESS;
    }
    else {
        BuildExplicitAccessWithName(&ea, Username,
            dwGrantAccess,
            SET_ACCESS, CONTAINER_INHERIT_ACE);
    }

    dwError = SetEntriesInAcl(1, &ea, pacl, &pNewAcl);
    if (dwError != ERROR_SUCCESS)
    {
        fprintf(stderr, "[-] SetEntriesInAcl failed(%d)\n", dwError);
        return FALSE;
    }

    // Initialize a new security descriptor.

    if (!InitializeSecurityDescriptor(&sd,
        SECURITY_DESCRIPTOR_REVISION))
    {
        fprintf(stderr, "[-] InitializeSecurityDescriptor failed(%d)\n", GetLastError());
        return FALSE;
    }

    // Set the new DACL in the security descriptor.

    if (!SetSecurityDescriptorDacl(&sd, TRUE, pNewAcl, FALSE))
    {
        fprintf(stderr, "[-] SetSecurityDescriptorDacl failed(%d)\n", GetLastError());
        return FALSE;
    }

    // Set the new DACL for the service object.

    if (!SetServiceObjectSecurity(hService,
        DACL_SECURITY_INFORMATION, &sd))
    {
        fprintf(stderr, "[-] SetServiceObjectSecurity failed(%d)\n", GetLastError());
        return FALSE;
    }

    fprintf(stdout, "[+] Service DACL updated successfully\n");
    return TRUE;
}

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
};

int main(int argc, char* argv[])
{
    CLI::App app{ "Play Doh Windows ACL Tools. - By Rvn0xsy\n[@] Blog : https://payloads.online/" };

    app.require_subcommand(1);

    // [ActiveDirectory]
    ADOptions* AD_options = new ADOptions();
    
    
   
    auto ActiveDirectoryExtendRights = app.add_subcommand("AD-ExtendRights", "ActiveDirectory ExtendRights");
    // ActiveDirectory->add_option("-h,--help", sActiveDirectoryExtendedRight, "ActiveDirectory ExtendedRight");
    ActiveDirectoryExtendRights->add_flag("-a,--add", AD_options->isActiveDirectoryAddRight, "Add Right to Object.");
    ActiveDirectoryExtendRights->add_flag("-r,--remove", AD_options->isActiveDirectoryRemoveRight, "Remove ActiveDirectory ExtendedRight");
    ActiveDirectoryExtendRights->add_option("-u,--user", AD_options->sActiveDirectoryUser, "Username,e.g. DomainName\\Rvn0xsy.");
    ActiveDirectoryExtendRights->add_option("-e,--extended-right", AD_options->sActiveDirectoryExtendedRight, "ActiveDirectory ExtendedRight");
    ActiveDirectoryExtendRights->add_option("-s,--server", AD_options->sLdapPath, "ActiveDirectory Server LDAP Path.");
    ActiveDirectoryExtendRights->add_flag("-l,--list", AD_options->isListActiveDirectoryExtendedRights, "List All ActiveDirectory ExtendedRights .");


    ActiveDirectoryExtendRights->callback([&]() {

        HRESULT hr = NULL;
        IADs* pObject = NULL;

        if (AD_options->isListActiveDirectoryExtendedRights) {
            std::cout << "[*] ActiveDirectory Extended Rights : " << std::endl;

            for (auto& right : ADExtendedRightsMap) {
                std::cout << "[*] " << right.first << std::endl;
            }
            return 0;
        }

        if (ADExtendedRightsMap.find(AD_options->sActiveDirectoryExtendedRight) == ADExtendedRightsMap.end()) {
            std::cout << "[*] Not Found ActiveDirectoryExtendedRight ." << std::endl;
            std::cout << "[+] Example :" << std::endl;
            std::cout << "[+] Help : PDAcl.exe AD -h" << std::endl;
            std::cout << "[+] List ALL ActiveDirectory ExtendedRights : PDAcl.exe AD -l" << std::endl;
            std::cout << "[+] Add ActiveDirectory ExtendedRights : PDAcl.exe AD -a -e <ExtendedRights> -u Domain\\Someone -s DC=Domain,DC=com" << std::endl;
            std::cout << "[+] Remove ActiveDirectory ExtendedRights : PDAcl.exe AD -r -e <ExtendedRights> -u Domain\\Someone -s DC=Domain,DC=com" << std::endl;
            return 0;
        }

        // 尝试初始化安全对象
        hr = CoInitialize(NULL);
        if (!SUCCEEDED(hr)) {
            std::cout << "[*] Initialize Error : " << hr << std::endl;
            return 0;
        }

        std::cout << "[*] ActiveDirectoryExtended Right: " << AD_options->sActiveDirectoryExtendedRight << std::endl;
        if (AD_options->sActiveDirectoryExtendedRight.empty() || AD_options->sLdapPath.empty() || AD_options->sActiveDirectoryUser.empty()) {
            std::cout << "[*] Not Input ActiveDirectoryExtendedRight Or LDAP Path Or Username." << std::endl;
            std::cout << app.help() << std::endl;
            return 0;
        }

        // 获取LDAP路径
        std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
        std::wstring ADsPath(L"LDAP://");
        ADsPath.append(converter.from_bytes(AD_options->sLdapPath));
        std::wstring wsActiveDirectoryUser;
        wsActiveDirectoryUser.append(converter.from_bytes(AD_options->sActiveDirectoryUser));

        std::cout << "[*] Server : " << AD_options->sLdapPath << std::endl;
        hr = ADsGetObject(ADsPath.c_str(), IID_IADs, (void**)&pObject);


        if (!SUCCEEDED(hr)) {
            std::cout << "[*] ADsGetObject Error : " << hr << std::endl;
            return 0;
        }
        if (AD_options->isActiveDirectoryAddRight) {
            std::cout << "[*] Add Right : " << AD_options->sActiveDirectoryExtendedRight << std::endl;
        }
        else if (AD_options->isActiveDirectoryRemoveRight) {
            std::cout << "[*] Remove Right : " << AD_options->sActiveDirectoryExtendedRight << std::endl;
        }
        // 修改权限
        hr = ADSetExtendedRight(
            pObject,
            (LPWSTR)ADExtendedRightsMap[AD_options->sActiveDirectoryExtendedRight].data(),
            ADS_ACETYPE_ACCESS_ALLOWED_OBJECT,
            ADS_ACEFLAG_INHERIT_ACE,
            NULL,
            (LPWSTR)wsActiveDirectoryUser.data(),
            AD_options->isActiveDirectoryAddRight
        );

        if (!SUCCEEDED(hr)) {
            std::cout << "[*] Modfiy ActiveDirectoryExtendedRight Failed " << AD_options->sActiveDirectoryExtendedRight << " right : " << hr << std::endl;
            std::cout << "[*] Return Error : " << hr << std::endl;
        }
        else {
            std::cout << "[*] Modfiy ActiveDirectoryExtendedRight Success " << AD_options->sActiveDirectoryExtendedRight << " extended right!!! " << std::endl;
        }

        // Release the object.
        pObject->Release();
        // Uninitialize COM.
        CoUninitialize();

        return 0;
    });


    // [ActiveDirectory Rights]
    

    auto ActiveDirectoryRights = app.add_subcommand("AD-Rights", "ActiveDirectory Rights");
    
    ActiveDirectoryRights->add_flag("-a,--add", AD_options->isActiveDirectoryAddRight, "Add Right to Object.");
    ActiveDirectoryRights->add_flag("-r,--remove", AD_options->isActiveDirectoryRemoveRight, "Remove ActiveDirectory Right");
    ActiveDirectoryRights->add_option("-u,--user", AD_options->sActiveDirectoryUser, "Username,e.g. DomainName\\Rvn0xsy.");
    ActiveDirectoryRights->add_option("-e,--extended-right", AD_options->sActiveDirectoryRight, "ActiveDirectory Right");
    ActiveDirectoryRights->add_option("-s,--server", AD_options->sLdapPath, "ActiveDirectory Server LDAP Path.");
    ActiveDirectoryRights->add_flag("-l,--list", AD_options->isListActiveDirectoryRights, "List All ActiveDirectory Rights .");

    ActiveDirectoryRights->callback([&]() {

        HRESULT hr = NULL;
        IADs* pObject = NULL;

        if (AD_options->isListActiveDirectoryRights) {
            std::cout << "[*] ActiveDirectory Rights : " << std::endl;
            auto index = 0;
            for (auto& right : ADRightsMap) {
                std::cout << "["  << index << "]\t" << right.first << std::endl;
                index++;
            }
            return 0;
        }

        if (ADRightsMap.find(AD_options->sActiveDirectoryRight) == ADRightsMap.end()) {
            std::cout << "[*] Not Found ActiveDirectory Right ." << std::endl;
            std::cout << "[+] Example :" << std::endl;
            std::cout << "[+] Help : PDAcl.exe AD -h" << std::endl;
            std::cout << "[+] List ALL ActiveDirectory Rights : PDAcl.exe AD -l" << std::endl;
            std::cout << "[+] Add ActiveDirectory Rights : PDAcl.exe AD -a -e <Rights> -u Domain\\Someone -s DC=Domain,DC=com" << std::endl;
            std::cout << "[+] Remove ActiveDirectory Rights : PDAcl.exe AD -r -e <Rights> -u Domain\\Someone -s DC=Domain,DC=com" << std::endl;
            return 0;
        }

        // 尝试初始化安全对象
        hr = CoInitialize(NULL);
        if (!SUCCEEDED(hr)) {
            std::cout << "[*] Initialize Error : " << hr << std::endl;
            return 0;
        }

        std::cout << "[*] ActiveDirectory Right: " << AD_options->sActiveDirectoryRight << std::endl;
        if (AD_options->sActiveDirectoryRight.empty() || AD_options->sLdapPath.empty() || AD_options->sActiveDirectoryUser.empty()) {
            std::cout << "[*] Not Input ActiveDirectoryRight Or LDAP Path Or Username." << std::endl;
            std::cout << app.help() << std::endl;
            return 0;
        }

        // 获取LDAP路径
        std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
        std::wstring ADsPath(L"LDAP://");
        ADsPath.append(converter.from_bytes(AD_options->sLdapPath));
        std::wstring wsActiveDirectoryUser;
        wsActiveDirectoryUser.append(converter.from_bytes(AD_options->sActiveDirectoryUser));

        std::cout << "[*] Server : " << AD_options->sLdapPath << std::endl;
        hr = ADsGetObject(ADsPath.c_str(), IID_IADs, (void**)&pObject);


        if (!SUCCEEDED(hr)) {
            std::cout << "[*] ADsGetObject Error : " << hr << std::endl;
            return 0;
        }
        if (AD_options->isActiveDirectoryAddRight) {
            std::cout << "[*] Add Right : " << AD_options->sActiveDirectoryRight << std::endl;
        }
        else if (AD_options->isActiveDirectoryRemoveRight) {
            std::cout << "[*] Remove Right : " << AD_options->sActiveDirectoryRight << std::endl;
        }

        // 修改权限
        hr = ADSetRight(
            pObject,
            ADRightsMap[AD_options->sActiveDirectoryRight],
            ADS_ACETYPE_ACCESS_ALLOWED_OBJECT,
            ADS_ACEFLAG_INHERIT_ACE,
            NULL,
            NULL,
            (LPWSTR)wsActiveDirectoryUser.data(),
            AD_options->isActiveDirectoryAddRight
        );

        if (!SUCCEEDED(hr)) {
            std::cout << "[*] Modfiy ActiveDirectory Right Failed " << AD_options->sActiveDirectoryRight << " right : " << hr << std::endl;
            std::cout << "[*] Return Error : " << hr << ", Error : " << GetLastError() << std::endl;
        }
        else {
            std::cout << "[*] Modfiy ActiveDirectory Right Success " << AD_options->sActiveDirectoryRight << " extended right!!! " << std::endl;
        }

        // Release the object.
        pObject->Release();
        // Uninitialize COM.
        CoUninitialize();

        return 0;


    });


    std::string sServiceName = "";
    std::string sServiceRight = "";
    std::string sServiceUserName = "";
    bool isListServiceRights = false;
    bool isServiceAddRight = false;
    bool isServiceRemoveRight = false;
    auto ServiceRights = app.add_subcommand("Service", "Service Rights");
    ServiceRights->add_flag("-a,--add", isServiceAddRight, "Add Right to Service.");
    ServiceRights->add_flag("-r,--remove", isServiceRemoveRight, "Remove Right to Service.");
    ServiceRights->add_option("-u,--user", sServiceUserName, "Username,e.g. Everyone.");
    ServiceRights->add_option("-e,--extended-right", sServiceRight, "Service Right");
    ServiceRights->add_option("-s,--service", sServiceName, "ServiceName.");
    ServiceRights->add_flag("-l,--list", isListServiceRights, "List All Service Rights .");

    ServiceRights->callback([&]() {
        // 列出所有权限
        if (isListServiceRights) {
            std::cout << "[*] Service Rights : " << std::endl;
            for (auto& right : ServiceRightsMap) {
                std::cout << "[*] " << right.first << std::endl;
            }

            return 0;
        }

        // 检查权限
        if (ServiceRightsMap.find(sServiceRight) == ServiceRightsMap.end()) {
            std::cout << "[*] Not Found Service Right ." << std::endl;
            std::cout << "[+] Example :" << std::endl;
            std::cout << "[+] Help : PDAcl.exe Service -h" << std::endl;
            std::cout << "[+] List ALL Service Rights : PDAcl.exe Service -l" << std::endl;
            std::cout << "[+] Add Service Rights : PDAcl.exe AD -a -e <Rights> -u Everyone -s ServiceName" << std::endl;
            std::cout << "[+] Remove Service Rights : PDAcl.exe Service -r -e <Rights> -u Everyone -s ServiceName" << std::endl;
            return 0;
        }
        std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;

        if (isServiceAddRight) {
            std::cout << "[*] Add Service " << sServiceName << " Right..." << std::endl;
        }
        else {
            std::cout << "[*] Remove Service " << sServiceName << " Right..." << std::endl;
        }

        BOOL isRes = ModifyServiceACL(
            (LPTSTR)converter.from_bytes(sServiceName).c_str(),
            (LPTSTR)converter.from_bytes(sServiceUserName).c_str(),
            ServiceRightsMap[sServiceRight],
            isServiceAddRight
        );

        if (isRes) {
            std::cout << "[+] Successful operation." << std::endl;
        }
        else {
            std::cout << "[+] Operation failed." << std::endl;
        }

        return 0;
    });

    try {
        CLI11_PARSE(app, argc, argv);
    }
    catch (const CLI::ParseError& e) {
        std::cout << app.help() << std::endl;
        return app.exit(e);
    }

    return GetLastError();
 
}
