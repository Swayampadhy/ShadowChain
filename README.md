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

### Detailed Steps

1. **Retrieve Volume Serial Number**:
   ```
   DWORD dwSerialNumber = 0x00;
if (!GetVolumeInformationW(L"C:\\", NULL, 0x00, &dwSerialNumber, NULL, NULL, NULL, 0x00) || dwSerialNumber == 0x00) {
    printf("[!] GetVolumeInformationW Failed With Error: %d \n", GetLastError());
    return FALSE;
}
   ```
    - The function uses `GetVolumeInformationW` to retrieve the volume serial number of the C: drive.
    - If the function fails or the serial number is zero, it prints an error message and returns `FALSE`.

2. **Compare Serial Number with Stored Value**:
    
    

