#include "service.h"

extern std::map<std::string, INT> ServiceRightsMap{
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

VOID ServiceCallBack(ServiceOptions* Options)
{

    if (!Options->logonUser.empty()) {
        if (UtilsSwitchUser(Options->logonUser) == FALSE)
            return;
    }

    // 列出所有权限
    if (Options->isListServiceRights) {
        std::cout << "[*] Service Rights : " << std::endl;
        for (auto& right : ServiceRightsMap) {
            std::cout << "[*] " << right.first << std::endl;
        }

        return;
    }

    // 检查权限
    if (ServiceRightsMap.find(Options->sServiceRight) == ServiceRightsMap.end()) {
        std::cout << "[*] Not Found Service Right ." << std::endl;
        std::cout << "[+] Example :" << std::endl;
        std::cout << "[+] Help : PDAcl.exe Service -h" << std::endl;
        std::cout << "[+] List ALL Service Rights : PDAcl.exe Service -l" << std::endl;
        std::cout << "[+] Add Service Rights : PDAcl.exe AD -a -e <Rights> -u Everyone -s ServiceName" << std::endl;
        std::cout << "[+] Remove Service Rights : PDAcl.exe Service -r -e <Rights> -u Everyone -s ServiceName" << std::endl;
        return;
    }
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;

    if (Options->isServiceAddRight) {
        std::cout << "[*] Add Service " << Options->sServiceName << " Right..." << std::endl;
    }
    else {
        std::cout << "[*] Remove Service " << Options->sServiceName << " Right..." << std::endl;
    }

    BOOL isRes = ModifyServiceACL(
        (LPTSTR)converter.from_bytes(Options->sServiceName).c_str(),
        (LPTSTR)converter.from_bytes(Options->sServiceUserName).c_str(),
        ServiceRightsMap[Options->sServiceRight],
        Options->isServiceAddRight
    );

    if (isRes) {
        std::cout << "[+] Successful operation." << std::endl;
    }
    else {
        std::cout << "[+] Operation failed." << std::endl;
    }
    return VOID();
}

