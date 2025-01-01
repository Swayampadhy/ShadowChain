// Header file for anti-debugging functions
#pragma once

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

// Function to check NtQueryInformationProcess and determine if the process is being debugged
BOOL NtQIPDebuggerCheck() {

	NTSTATUS                      STATUS = NULL;
	fnNtQueryInformationProcess   pNtQueryInformationProcess = NULL;
	DWORD64                       dwIsDebuggerPresent = NULL;
	DWORD64                       hProcessDebugObject = NULL;

	// Getting the address of NtQueryInformationProcess
	pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) {
		printf("[!] GetProcAddress Failed With Error Code: %d\n", GetLastError());
		return FALSE;
	}

	// Calling NtQueryInformationProcess with ProcessDebugPort flag
	STATUS = pNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwIsDebuggerPresent, sizeof(DWORD64), NULL);
	if (STATUS != 0x0) {
		printf("[!] NtQueryInformationProcess [1] Failed With Error Code: %d\n", GetLastError());
		return FALSE;
	}

	// Checking if the process is being debugged
	if (dwIsDebuggerPresent != 0) {
		printf("[!] Process is being debugged\n");
		return TRUE;
	}

	// Calling NtQueryInformationProcess with ProcessDebugObjectHandle flag
	STATUS = pNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &hProcessDebugObject, sizeof(DWORD64), NULL);
	if (STATUS != 0x0 && STATUS != 0Xc0000353) {
		printf("[!] NtQueryInformationProcess [2] Failed With Error Code: %d\n", GetLastError());
		return FALSE;
	}

	// Checking if the process is being debugged
	if (hProcessDebugObject != 0) {
		printf("[!] Process is being debugged\n");
		return TRUE;
	}

	// TRUE = being debugged, FALSE = not being debugged
}

// Can add more debugging checks here below