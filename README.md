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
    

