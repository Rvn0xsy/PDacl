#include "utils.h"

BOOL UtilsSwitchUser(std::string logonUser)
{
	// Domain/Username@Password
	HANDLE hToken = NULL;
	size_t st_spit = logonUser.find_first_of('/');
	size_t st_at = logonUser.find_first_of('@');
	std::string domain = logonUser.substr(0, st_spit);
	std::string user = logonUser.substr(st_spit+1, st_at-st_spit-1);
	std::string pass = logonUser.substr(st_at+1);
	// LogonUserA()
	if (LogonUserA(user.c_str(), domain.c_str(), pass.c_str(), LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &hToken)) {
		if (ImpersonateLoggedOnUser(hToken)) {
			std::cout << "[+] ImpersonateLoggedOnUser Success !" << std::endl;
			return TRUE;
		}
		std::cout << "[-] ImpersonateLoggedOnUser Failed : " << GetLastError() << std::endl;
	}
	else {
		std::cout << "[-] Can't Login ...." << GetLastError() << std::endl;
	}
	return FALSE;
}
