#include <Windows.h>
#include <stdio.h>

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

SIZE_T StringLengthA(LPCSTR String) { 
    LPCSTR String2; 
    for (String2 = String; *String2; ++String2);
    printf("%lld\n", String2 - String);
    return (String2 - String); 
}

BOOL CreateFraction(PBYTE DataBlock, DWORD dwWriteSize, PWCHAR OutputDirectory) {
    HANDLE hHandle = INVALID_HANDLE_VALUE;
    WCHAR OutputPath[MAX_PATH * sizeof(WCHAR)] = { 0 };
    DWORD dwOut = ERROR_SUCCESS;
    BOOL bFlag = FALSE;
    CHAR FileHeader[MAX_PATH] = { 0 };

    for (DWORD dwFractionCount = 0;; dwFractionCount++) {
        _snwprintf_s(OutputPath, MAX_PATH * sizeof(WCHAR), L"%wsFraction%ld", OutputDirectory, dwFractionCount);
        if (IsPathValidW(OutputPath)) {
            continue;
        }
        else {
            _snprintf_s(FileHeader, MAX_PATH, "<%ld>", dwFractionCount);

            if (strlen(FileHeader) < 32) {
                DWORD dwOffset = (DWORD)(32 - strlen(FileHeader));
                for (DWORD dwX = 0; dwX < dwOffset; dwX++) {
                    strcat_s(FileHeader, sizeof(FileHeader), " ");
                }
                break;
            }
        }

        hHandle = CreateFileW(OutputPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hHandle == INVALID_HANDLE_VALUE) {
            wprintf(L"Failed to create file: %ls\n", OutputPath);
            goto EXIT_ROUTINE;
        }

        if (!WriteFile(hHandle, FileHeader, 32, &dwOut, NULL)) {
            wprintf(L"Failed to write file header to: %ls\n", OutputPath);
            goto EXIT_ROUTINE;
        }
        dwOut = ERROR_SUCCESS;

        if (!WriteFile(hHandle, DataBlock, dwWriteSize, &dwOut, NULL)) {
            wprintf(L"Failed to write data block to: %ls\n", OutputPath);
            goto EXIT_ROUTINE;
        }

        wprintf(L"Successfully created fraction file: %ls\n", OutputPath);
        bFlag = TRUE;
        break;
    }

EXIT_ROUTINE:

    if (hHandle)
        CloseHandle(hHandle);
    if (!bFlag) {
        printf("Error in CreateFraction\n");
    }
    return bFlag;
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

   INT Arguments;
   LPWSTR* szArgList = CommandLineToArgvW(GetCommandLineW(), &Arguments);    

   if (Arguments < 3) {
       printf("Usage: <program> <input file> <output directory>\n");
       return ERROR_INVALID_PARAMETER;
    }

    wprintf(L"Reading file\n");
    hHandle = CreateFileW(szArgList[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    // Convert ".\test.exe" to wide string
//    WCHAR wszTestExe[MAX_PATH];
//    MultiByteToWideChar(CP_ACP, 0, ".\\test.exe", -1, wszTestExe, MAX_PATH);

    wprintf(L"Attempting to open file\n");

    // Convert ".\opfolder\" to wide string
 //   WCHAR wszOpFolder[MAX_PATH];
 //   MultiByteToWideChar(CP_ACP, 0, ".\\opfolder\\", -1, wszOpFolder, MAX_PATH);

 //   hHandle = CreateFileW(wszTestExe, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hHandle == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to open file: %ls\n", szArgList[1]);
        goto EXIT_ROUTINE;
    }

    do {
        BYTE Buffer[1024] = { 0 };
        DWORD dwRead = ERROR_SUCCESS;

        if (!ReadFile(hHandle, Buffer, 1024, &dwRead, NULL)) {
            printf("Failed to read file\n");
            goto EXIT_ROUTINE;
        }

        if (dwRead < 1024) {
            EndOfFile = TRUE;
        }

       if (!CreateFraction(Buffer, dwRead, szArgList[2])) {
//        if (!CreateFraction(Buffer, dwRead, wszOpFolder)) {
            printf("Failed to create fraction\n");
            goto EXIT_ROUTINE;
        }

        ZeroMemory(Buffer, sizeof(Buffer));
    
    } while (!EndOfFile);

    bFlag = TRUE;
    printf("Operation Completed Successfully\n");

EXIT_ROUTINE:

    if (!bFlag) {
        dwError = GetLastError();
        printf("Error: %ld\n", dwError);
    }
    LocalFree(szArgList);
    
    if (hHandle) {
        CloseHandle(hHandle);
    }
    return dwError;
}


