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

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	HANDLE hHandle = INVALID_HANDLE_VALUE;
	DWORD dwError = ERROR_SUCCESS;
	BOOL bFlag = FALSE;
	BOOL EndOfFile = FALSE;

	INT Arguments;
	LPWSTR* szArgList = CommandLineToArgvW(GetCommandLineW(), &Arguments);	
	
	hHandle = CreateFile(szArgList[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hHandle == INVALID_HANDLE_VALUE)
	{
		goto EXIT_ROUTINE;
	}
	
EXIT_ROUTINE:

	if (!bFlag)
		dwError = GetLastError();
	LocalFree(szArgList);
	if (hHandle)
		CloseHandle(hHandle);
	return dwError;
	
}