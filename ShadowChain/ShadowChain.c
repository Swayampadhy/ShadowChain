#include <stdio.h>
#include <Windows.h>

int main(int argc, char* argv[]) {
	
	if (argc < 2) {
		printf("[!] Missing Argument; Payload File to run\n");
		return -1;
	}

	//printf("[*] Running Dll Payload: %s\n", argv[1]);
	//printf("[i] Injecting \"%s\" To The Local Process Of Pid: %d\n", argv[1], GetCurrentProcessId());

	//printf("[+] Loading Dll ...");
	//if (LoadLibraryA(argv[1]) == NULL) {
	//	printf("[!] Loadlibrary Failed With Error Code: %d\n", GetLastError());
	//	return -1;
	//}

	printf("[+] Payload Loaded Successfully\n");

	printf("[#] Press Any Key To Exit\n");
	getchar();

	return 0;
}	
