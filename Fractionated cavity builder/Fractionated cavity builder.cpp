#include <Windows.h>
#include <stdio.h>

typedef struct __FRACTION_DATA {
    LONGLONG BufferSize;
    DWORD NumberOfFractions;
} FRACTION_DATA, * PFRACTION_DATA;

PBYTE g_BinaryBuffer = NULL;

BOOL IsPathValidW(PWCHAR FilePath) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    hFile = CreateFileW(FilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    if (hFile)
        CloseHandle(hFile);
    return TRUE;
}

BOOL GetFractionatedBinarySize(PWCHAR Path, PFRACTION_DATA FractionData) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW Data = { 0 };
    WCHAR BinarySearchPath[MAX_PATH * sizeof(WCHAR)] = { 0 };
    LONGLONG Size = 0;
    _snwprintf_s(BinarySearchPath, MAX_PATH * sizeof(WCHAR), L"%ws*", Path);
    hFile = FindFirstFileW(BinarySearchPath, &Data);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    do {
        LARGE_INTEGER BinarySize = { 0 };
        BinarySize.HighPart = Data.nFileSizeHigh;
        BinarySize.LowPart = Data.nFileSizeLow;
        FractionData->BufferSize += BinarySize.QuadPart;
        if (BinarySize.QuadPart)
            FractionData->NumberOfFractions++;
    } while (FindNextFileW(hFile, &Data));
    if (hFile)
        FindClose(hFile);
    return TRUE;
}

VOID ByteArrayToCharArrayA(PCHAR Char, PBYTE Byte, DWORD Length) {
    for (DWORD dwX = 0; dwX < Length; dwX++) {
        Char[dwX] = (BYTE)Byte[dwX];
    }
}

BOOL GetFractionedOrdinal(PWCHAR Path, DWORD Ordinal) {
    HANDLE hHandle = INVALID_HANDLE_VALUE;
    CHAR CharString[32] = { 0 };
    CHAR OffsetInteger[3] = { 0 };
    DWORD dwOffset = 0;
    INT Offset;
    BYTE Buffer[32] = { 0 };
    if (!IsPathValidW(Path))
        return -1;
    hHandle = CreateFileW(Path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hHandle == INVALID_HANDLE_VALUE)
        return -1;
    if (!ReadFile(hHandle, Buffer, 32, NULL, NULL)) {
        CloseHandle(hHandle);
        return -1;
    }
    ByteArrayToCharArrayA(CharString, Buffer, 32);
    for (DWORD dwX = 0; dwX < 32; dwX++) {
        if (CharString[dwX] == ' ' || CharString[dwX] == '<' || CharString[dwX] == '>')
            continue;
        if (CharString[dwX] >= '0' && CharString[dwX] <= '9') {
            if (isdigit((UCHAR)CharString[dwX])) {
                OffsetInteger[dwOffset] = CharString[dwX];
                dwOffset++;
            }
        }
    }
    Offset = atoi(OffsetInteger);
    if (hHandle)
        CloseHandle(hHandle);
    if (Offset == Ordinal)
        return TRUE;
    else
        return FALSE;
}

BOOL LoadFractionIntoBuffer(PWCHAR Path, DWORD Ordinal) {
    HANDLE hHandle = INVALID_HANDLE_VALUE;
    BOOL bFlag = FALSE;
    BYTE FractionBuffer[1024] = { 0 };
    DWORD dwError = ERROR_SUCCESS;
    hHandle = CreateFileW(Path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hHandle == INVALID_HANDLE_VALUE)
        goto EXIT_ROUTINE;
    if (SetFilePointer(hHandle, 32, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
        goto EXIT_ROUTINE;
    if (!ReadFile(hHandle, FractionBuffer, 1024, &dwError, NULL))
        goto EXIT_ROUTINE;
    dwError = Ordinal * 1024;
    CopyMemory(g_BinaryBuffer + dwError, FractionBuffer, 1024);
    dwError = ERROR_SUCCESS;
    bFlag = TRUE;
EXIT_ROUTINE:
    if (hHandle)
        CloseHandle(hHandle);
    return bFlag;
}

DWORD GetFraction(PWCHAR Path, DWORD Ordinal) {
    WCHAR BinarySearchPath[MAX_PATH * sizeof(WCHAR)] = { 0 };
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW FindData = { 0 };
    BOOL bFlag = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    _snwprintf_s(BinarySearchPath, MAX_PATH * sizeof(WCHAR), L"%ws*", Path);
    hFind = FindFirstFileW(BinarySearchPath, &FindData);
    if (hFind == INVALID_HANDLE_VALUE)
        return FALSE;
    do {
        WCHAR BinaryPath[MAX_PATH * sizeof(WCHAR)] = { 0 };
        if (FindData.cFileName[0] == '.')
            continue;
        _snwprintf_s(BinaryPath, MAX_PATH * sizeof(WCHAR), L"%ws%ws", Path, FindData.cFileName);
        if (GetFractionedOrdinal(BinaryPath, Ordinal)) {
            if (!LoadFractionIntoBuffer(BinaryPath, Ordinal))
                goto EXIT_ROUTINE;
            break;
        }
        Sleep(1);
    } while (FindNextFileW(hFind, &FindData));
    dwError = ERROR_SUCCESS;
    bFlag = TRUE;
EXIT_ROUTINE:
    if (!bFlag)
        dwError = GetLastError();
    if (hFind)
        FindClose(hFind);
    return dwError;
}

BOOL AssembleFractionatedBinary(PWCHAR Path, PFRACTION_DATA FractionData) {
    DWORD dwError = ERROR_SUCCESS;
    BOOL bFlag = FALSE;
    for (DWORD dwX = 0; dwX < FractionData->NumberOfFractions; dwX++) {
        dwError = GetFraction(Path, dwX);
        if (dwError != ERROR_SUCCESS)
            goto EXIT_ROUTINE;
    }
    bFlag = TRUE;
EXIT_ROUTINE:
    if (!bFlag)
        dwError = GetLastError();
    return TRUE;
}

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd) {
    HANDLE hHandle = INVALID_HANDLE_VALUE;
    DWORD dwError = ERROR_SUCCESS;
    BOOL bFlag = FALSE;
    LONGLONG BufferSize = 0;
    FRACTION_DATA FractionData = { 0 };
    INT Arguments;
    LPWSTR* szArgList = CommandLineToArgvW(GetCommandLineW(), &Arguments);
    if (!GetFractionatedBinarySize(szArgList[1], &FractionData))
        goto EXIT_ROUTINE;
    g_BinaryBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FractionData.BufferSize + 1024); //offset
    if (g_BinaryBuffer == NULL)
        goto EXIT_ROUTINE;
    if (!AssembleFractionatedBinary(szArgList[1], &FractionData))
        goto EXIT_ROUTINE;
    hHandle = CreateFileW(szArgList[2], GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hHandle == INVALID_HANDLE_VALUE)
        goto EXIT_ROUTINE;
    if (!WriteFile(hHandle, g_BinaryBuffer, (DWORD)FractionData.BufferSize, &dwError, NULL))
        goto EXIT_ROUTINE;
    CloseHandle(hHandle);
    bFlag = TRUE;
EXIT_ROUTINE:
    if (!bFlag)
        dwError = GetLastError();
    if (g_BinaryBuffer)
        HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, g_BinaryBuffer);
    LocalFree(szArgList);
    return dwError;
}
