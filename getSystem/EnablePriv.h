#pragma once
#include<Windows.h>
#include<WinBase.h>
#include<stdio.h>
#include<securitybaseapi.h>

BOOL EnablePriv(void) {
	LUID debug_value, restore_value;
	BOOL lookup_debug, lookup_restore, token_info;
	HANDLE proc_token, current_handle;
	DWORD buffer_size;
	PTOKEN_PRIVILEGES all_token_privs;
	int RestoreFound = 0, DebugFound = 0;
	TOKEN_PRIVILEGES my_token;
	PTOKEN_PRIVILEGES p_mytoken;

	lookup_debug = LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &debug_value);
	lookup_restore = LookupPrivilegeValueA(NULL, "SeRestorePrivilege", &restore_value);
	if (!lookup_debug || !lookup_restore)
		return FALSE;

	//get handle to your token
	current_handle = GetCurrentProcess();
	BOOL handle_result = OpenProcessToken(current_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_READ, &proc_token); //TOKEN_QUERY required to access token
	if (!handle_result)
		return FALSE;

	//Get Token structure length
	GetTokenInformation(proc_token, TokenPrivileges, NULL, 0, &buffer_size); //This function always fails, but returns buffer_size

	//call GetTokenInformation again to get the struct data
	all_token_privs = (PTOKEN_PRIVILEGES)malloc(buffer_size);
	token_info = GetTokenInformation(proc_token, TokenPrivileges, all_token_privs, buffer_size, &buffer_size);
	if (!token_info)
		return FALSE;

	//Now we will check if SeDebugPrivilege & SeRestorePrivilege is in all_token_privs
	for (int x = 0; x < all_token_privs->PrivilegeCount; x++) {
		if ((all_token_privs->Privileges[x].Luid.LowPart == debug_value.LowPart) && (all_token_privs->Privileges[x].Luid.HighPart == debug_value.HighPart)) {
			printf("[+] SeDebugPrivilege Found\n");
			DebugFound++;
		}
		else if ((all_token_privs->Privileges[x].Luid.LowPart == restore_value.LowPart) && (all_token_privs->Privileges[x].Luid.HighPart == restore_value.HighPart)) {
			printf("[+] SeRestorePrivilege Found\n");
			RestoreFound++;
		}
		else if (DebugFound == 1 && RestoreFound == 1)
			break;
		else
			continue;
	}

	if (!DebugFound) {
		printf("[!] SeDebugPrivilege not found\n");
		return FALSE;
	}
	if (!RestoreFound) {
		printf("[!] SeRestorePrivilege not found\n");
		return FALSE;
	}

	//change the token privilege for SeRestore then
	//define the new token struct
	//to enable more than 1 privilege at a time, change the
	//ANYSIZE_ARRAY definition in winnt.h 
	my_token.PrivilegeCount = 1;
	my_token.Privileges[0].Luid = restore_value;
	my_token.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	//my_token.Privileges[1].Luid = debug_value;
	//my_token.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
	p_mytoken = &my_token;

	//now change the token 
	BOOL change_priv = AdjustTokenPrivileges(proc_token, FALSE, p_mytoken, 0, NULL, NULL);
	if (!change_priv)
		return FALSE;

	return TRUE;

}


