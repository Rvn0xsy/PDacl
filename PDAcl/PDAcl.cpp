// PDAcl.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//


#include "active_directory.h"
#include "service.h"

#include "CLI11.hpp"

#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "Adsiid.lib")
#pragma comment(lib, "Activeds.lib")


extern std::map<std::string, std::wstring> ADExtendedRightsMap;
extern std::map<std::string, INT> ServiceRightsMap;
extern std::map<std::string, INT> ADRightsMap;

int main(int argc, char* argv[])
{
    CLI::App app{ "Play Doh Windows ACL Tools. - By Rvn0xsy\n[@] Blog : https://payloads.online/" };

    app.require_subcommand(1);

    
    ADOptions* AD_options = new ADOptions();
    ServiceOptions* Service_options = new ServiceOptions();
    
    
    // [ActiveDirectory]
    auto ActiveDirectoryExtendRights = app.add_subcommand("ADE", "ActiveDirectory ExtendRights");
    ActiveDirectoryExtendRights->add_flag("-a,--add", AD_options->isActiveDirectoryAddRight, "Add Right to Object.");
    ActiveDirectoryExtendRights->add_flag("-r,--remove", AD_options->isActiveDirectoryRemoveRight, "Remove ActiveDirectory ExtendedRight");
    ActiveDirectoryExtendRights->add_option("-u,--user", AD_options->sActiveDirectoryUser, "Username,e.g. DomainName\\Rvn0xsy.");
    ActiveDirectoryExtendRights->add_option("-e,--extended-right", AD_options->sActiveDirectoryExtendedRight, "ActiveDirectory ExtendedRight");
    ActiveDirectoryExtendRights->add_option("-s,--server", AD_options->sLdapPath, "ActiveDirectory Server LDAP Path.");
    ActiveDirectoryExtendRights->add_flag("--list", AD_options->isListActiveDirectoryExtendedRights, "List All ActiveDirectory ExtendedRights .");
    ActiveDirectoryExtendRights->add_option("--login", AD_options->logonUser, "Login Use,e.g. Domain/Username@Password")->default_str("");


    ActiveDirectoryExtendRights->callback([&]() {
        ActiveDirectoryExtendRightsCallBack(AD_options);
        return 0;
    });


    // [ActiveDirectory Rights]
    
    auto ActiveDirectoryRights = app.add_subcommand("AD", "ActiveDirectory Rights");
    
    ActiveDirectoryRights->add_flag("-a,--add", AD_options->isActiveDirectoryAddRight, "Add Right to Object.");
    ActiveDirectoryRights->add_flag("-r,--remove", AD_options->isActiveDirectoryRemoveRight, "Remove ActiveDirectory Right");
    ActiveDirectoryRights->add_option("-u,--user", AD_options->sActiveDirectoryUser, "Username,e.g. DomainName\\Rvn0xsy.");
    ActiveDirectoryRights->add_option("-e,--extended-right", AD_options->sActiveDirectoryRight, "ActiveDirectory Right");
    ActiveDirectoryRights->add_option("-s,--server", AD_options->sLdapPath, "ActiveDirectory Server LDAP Path.");
    ActiveDirectoryRights->add_flag("--list", AD_options->isListActiveDirectoryRights, "List All ActiveDirectory Rights .");
    ActiveDirectoryRights->add_option("--login", AD_options->logonUser, "Login Use,e.g. Domain/Username@Password")->default_str("");

    ActiveDirectoryRights->callback([&]() {
        ActiveDirectoryRightsCallBack(AD_options);
        return 0;
    });


    
    auto ServiceRights = app.add_subcommand("SC", "Service Rights");
    ServiceRights->add_flag("-a,--add", Service_options->isServiceAddRight, "Add Right to Service.");
    ServiceRights->add_flag("-r,--remove", Service_options->isServiceRemoveRight, "Remove Right to Service.");
    ServiceRights->add_option("-u,--user", Service_options->sServiceUserName, "Username,e.g. Everyone.");
    ServiceRights->add_option("-e,--extended-right", Service_options->sServiceRight, "Service Right");
    ServiceRights->add_option("-s,--service", Service_options->sServiceName, "ServiceName.");
    ServiceRights->add_flag("--list", Service_options->isListServiceRights, "List All Service Rights .");
    ServiceRights->add_option("--login", Service_options->logonUser, "Login Use,e.g. Domain/Username@Password")->default_str("");

    ServiceRights->callback([&]() {
        ServiceCallBack(Service_options);
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
