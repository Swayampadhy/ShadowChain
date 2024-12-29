#include <Windows.h>
#include <stdio.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	HANDLE hHandle = INVALID_HANDLE_VALUE;
	DWORD dwError = ERROR_SUCCESS;
	BOOL bFlag = FALSE;
	BOOL EndOfFile = FALSE;

	INT Arguments;
	LPWSTR* szArgList = CommandLineToArgvW(GetCommandLineW(), &Arguments);	
	if(!bFlag)
		dwError = GetLastError();
	LocalFree(szArgList);
	if (hHandle)
		CloseHandle(hHandle);
	return dwError;
}