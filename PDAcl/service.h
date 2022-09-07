#pragma once
#include <Windows.h>
#include <string>
#include <map>
#include <AclAPI.h>
#include <string>
#include <iostream>
#include <codecvt>
#include "utils.h"

typedef struct ServiceOptions{
    std::string sServiceName = "";
    std::string sServiceRight = "";
    std::string sServiceUserName = "";
    bool isListServiceRights = false;
    bool isServiceAddRight = false;
    bool isServiceRemoveRight = false;
    std::string logonUser = "";
};


BOOL ModifyServiceACL(
    LPTSTR ServiceName,
    LPTSTR Username,
    DWORD dwGrantAccess,
    BOOL isAdd 
);

VOID ServiceCallBack(ServiceOptions* Options);