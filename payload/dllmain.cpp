#include "pch.h"

// Function to store the payload
VOID Payload() {
	MessageBoxA(NULL, "Payload", "Payload", MB_OK | MB_ICONINFORMATION);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  dwReason,
                       LPVOID lpReserved
                     )
{
    switch (dwReason)
    {
    // Runs the payload when a process is attached to it
    case DLL_PROCESS_ATTACH: {
		Payload();
		break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    // Breaks when detached
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}

