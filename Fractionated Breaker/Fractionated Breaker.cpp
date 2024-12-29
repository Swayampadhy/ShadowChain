#include <Windows.h>
#include <stdio.h>

typedef struct __FRACTION_DATA {
	LONGLONG BufferSize;
	DWORD NumberOfFractions;
} FRACTION_DATA, * PFRACTION_DATA;

PBYTE g_BinaryBuffer = NULL;

BOOL IsPathValidW(PWCHAR FilePath) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFile(FilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	if (hFile)
		CloseHandle(hFile);
	return TRUE;
}

SIZE_T StringLengthA(LPCSTR String) { LPCSTR String2; for (String2 = String; *String2; ++String2); return (String2 - String); }

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
			goto EXIT_ROUTINE;
		}

		if (!WriteFile(hHandle, FileHeader, 32, &dwOut, NULL)) {
			goto EXIT_ROUTINE;
		}
		dwOut = ERROR_SUCCESS;

		if (!WriteFile(hHandle, DataBlock, dwWriteSize, &dwOut, NULL)) {
			goto EXIT_ROUTINE;
		}
	}

	EXIT_ROUTINE:

		if (hHandle)
			CloseHandle(hHandle);
		printf("Error");
		return bFlag;

}

int WINAPI WinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPSTR lpCmdLine,
    _In_ int nCmdShow
)
{
	HANDLE hHandle = INVALID_HANDLE_VALUE;
	DWORD dwError = ERROR_SUCCESS;
	BOOL bFlag = FALSE;
	BOOL EndOfFile = FALSE;

	INT Arguments;
	LPWSTR* szArgList = CommandLineToArgvW(GetCommandLineW(), &Arguments);	
	
	hHandle = CreateFile(szArgList[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	printf("File read: %ws\n", szArgList[1]);
	if (hHandle == INVALID_HANDLE_VALUE)
	{
		goto EXIT_ROUTINE;
	}

	do {
		BYTE Buffer[1024] = { 0 };
		DWORD dwRead = ERROR_SUCCESS;

		if (!ReadFile(hHandle, Buffer, 1024, &dwRead, NULL)) {
			goto EXIT_ROUTINE;
		}

		if (dwRead < 1024) {
			EndOfFile = TRUE;
		}

		if (!CreateFraction(Buffer, dwRead, szArgList[2])) {
			goto EXIT_ROUTINE;
		}

		ZeroMemory(Buffer, sizeof(Buffer));
	} while (!EndOfFile);

	bFlag = TRUE;

EXIT_ROUTINE:

	
	if (!bFlag)
		dwError = GetLastError();
	printf("Error: %ld\n", dwError);
	LocalFree(szArgList);
	if (hHandle)
		CloseHandle(hHandle);
	return dwError;
	
}