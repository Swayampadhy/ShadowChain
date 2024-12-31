#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

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
		if(hSnapShot !=NULL)
			CloseHandle(hSnapShot);
		if (*dwProcessID == NULL || *hProcess == NULL)
			return FALSE;
		return TRUE;
}

int main(int argc, char* argv[]) {
	
	// Get Command Line Arguments
	if (argc < 2) {
		printf("[!] Missing Argument; Payload File to run\n");
		return -1;
	}

	printf("[*] Running Dll Payload: %s\n", argv[1]);
	
	// Load the Dll into the local process
	printf("[i] Injecting \"%s\" To The Local Process Of Pid: %d\n", argv[1], GetCurrentProcessId());
	printf("[+] Loading Dll ...");
	if (LoadLibraryA(argv[1]) == NULL) {
		printf("[!] Loadlibrary Failed With Error Code: %d\n", GetLastError());
		return -1;
	}
	printf("[+] Payload Loaded Successfully\n");

	//End
	printf("[#] Press Any Key To Exit\n");
	getchar();

	return 0;
}	
