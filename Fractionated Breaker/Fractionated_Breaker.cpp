#include <Windows.h>
#include <stdio.h>
// Function to check if path is valid
BOOL IsPathValidW(PWCHAR FilePath) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    hFile = CreateFileW(FilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"Invalid file path: %ls\n", FilePath);
        return FALSE;
    }
    if (hFile) {
        CloseHandle(hFile);
    }
    return TRUE;
}

// Function to get the length of a string
SIZE_T StringLengthA(LPCSTR String) { 
    LPCSTR String2; 
    for (String2 = String; *String2; ++String2);
    printf("%lld\n", String2 - String);
    return (String2 - String); 
}

BOOL CreateFraction(PBYTE DataBlock, DWORD dwWriteSize, PWCHAR OutputDirectory) {
    HANDLE hHandle = INVALID_HANDLE_VALUE;
    WCHAR szFractionPath[MAX_PATH] = { 0 };
    static DWORD dwFractionCounter = 0;
    DWORD dwBytesWritten = 0;
    
    // Create directory if it doesn't exist
    if (!CreateDirectoryW(OutputDirectory, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        wprintf(L"Failed to create directory: %ls\n", OutputDirectory);
        return FALSE;
    }

    // Construct fraction path
    swprintf_s(szFractionPath, MAX_PATH, L"%ls\\Fraction%d", OutputDirectory, dwFractionCounter++);

    // Create file
    hHandle = CreateFileW(
        szFractionPath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
	// Check if file handle is valid
    if (hHandle == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to create file: %ls\n", szFractionPath);
        return FALSE;
    }

    // Write data
    if (!WriteFile(hHandle, DataBlock, dwWriteSize, &dwBytesWritten, NULL)) {
        wprintf(L"Failed to write to file: %ls\n", szFractionPath);
        CloseHandle(hHandle);
        return FALSE;
    }
	// Close file handle
    CloseHandle(hHandle);
    return TRUE;
}


int WINAPI WinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPSTR lpCmdLine,
    _In_ int nShowCmd
)
{
    wprintf(L"Program started\n");

    HANDLE hHandle = INVALID_HANDLE_VALUE;
    DWORD dwError = ERROR_SUCCESS;
    BOOL bFlag = FALSE;
    BOOL EndOfFile = FALSE;
	// Get command line arguments
   INT Arguments;
   LPWSTR* szArgList = CommandLineToArgvW(GetCommandLineW(), &Arguments);    

   if (Arguments < 3) {
       printf("Usage: <program> <input file> <output directory>\n");
       return ERROR_INVALID_PARAMETER;
    }
   // Create file handle to target program
    wprintf(L"Reading file\n");
    hHandle = CreateFileW(szArgList[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    wprintf(L"Attempting to open file\n");
	// Check if file handle is valid
    if (hHandle == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to open file: %ls\n", szArgList[1]);
        goto EXIT_ROUTINE;
    }

    do {
        BYTE Buffer[1024] = { 0 };
        DWORD dwRead = ERROR_SUCCESS;
		// Read file
        if (!ReadFile(hHandle, Buffer, 1024, &dwRead, NULL)) {
            printf("Failed to read file\n");
            goto EXIT_ROUTINE;
        }

        if (dwRead < 1024) {
            EndOfFile = TRUE;
        }
		// Create fractions of file
       if (!CreateFraction(Buffer, dwRead, szArgList[2])) {
            printf("Failed to create fraction\n");
            goto EXIT_ROUTINE;
        }

        ZeroMemory(Buffer, sizeof(Buffer));
    
    } while (!EndOfFile);
	// Set binary flag to true
    bFlag = TRUE;
    printf("Operation Completed Successfully\n");

EXIT_ROUTINE:
	// Free memory
    if (!bFlag) {
        dwError = GetLastError();
        printf("Error: %ld\n", dwError);
    }
    LocalFree(szArgList);
	// Close file handle
    if (hHandle) {
        CloseHandle(hHandle);
    }
    return dwError;
}


