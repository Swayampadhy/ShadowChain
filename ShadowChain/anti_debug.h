// Header file for anti-debugging functions
#pragma once

// Typedef for NtSystemDebugControl
typedef enum _SYSDBG_COMMAND
{
    SysDbgQueryModuleInformation,
    SysDbgQueryTraceInformation,
    SysDbgSetTracepoint,
    SysDbgSetSpecialCall, // PVOID
    SysDbgClearSpecialCalls, // void
    SysDbgQuerySpecialCalls,
    SysDbgBreakPoint,
    SysDbgQueryVersion, // DBGKD_GET_VERSION64
    SysDbgReadVirtual, // SYSDBG_VIRTUAL
    SysDbgWriteVirtual, // SYSDBG_VIRTUAL
    SysDbgReadPhysical, // SYSDBG_PHYSICAL // 10
    SysDbgWritePhysical, // SYSDBG_PHYSICAL
    SysDbgReadControlSpace, // SYSDBG_CONTROL_SPACE
    SysDbgWriteControlSpace, // SYSDBG_CONTROL_SPACE
    SysDbgReadIoSpace, // SYSDBG_IO_SPACE
    SysDbgWriteIoSpace, // SYSDBG_IO_SPACE
    SysDbgReadMsr, // SYSDBG_MSR
    SysDbgWriteMsr, // SYSDBG_MSR
    SysDbgReadBusData, // SYSDBG_BUS_DATA
    SysDbgWriteBusData, // SYSDBG_BUS_DATA
    SysDbgCheckLowMemory, // 20
    SysDbgEnableKernelDebugger,
    SysDbgDisableKernelDebugger,
    SysDbgGetAutoKdEnable,
    SysDbgSetAutoKdEnable,
    SysDbgGetPrintBufferSize,
    SysDbgSetPrintBufferSize,
    SysDbgGetKdUmExceptionEnable,
    SysDbgSetKdUmExceptionEnable,
    SysDbgGetTriageDump, // SYSDBG_TRIAGE_DUMP
    SysDbgGetKdBlockEnable, // 30
    SysDbgSetKdBlockEnable,
    SysDbgRegisterForUmBreakInfo,
    SysDbgGetUmBreakPid,
    SysDbgClearUmBreakPid,
    SysDbgGetUmAttachPid,
    SysDbgClearUmAttachPid,
    SysDbgGetLiveKernelDump, // SYSDBG_LIVEDUMP_CONTROL
    SysDbgKdPullRemoteFile, // SYSDBG_KD_PULL_REMOTE_FILE
    SysDbgMaxInfoClass
} SYSDBG_COMMAND, * PSYSDBG_COMMAND;

// NtSystemDebugControl structure
typedef NTSTATUS(NTAPI* fnNtSystemDebugControl)(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);

//Function to check if the process is being debugged
BOOL AntiDbgNtSystemDebugControl() {

    NTSTATUS                    STATUS = 0x00;
    fnNtSystemDebugControl      pNtSystemDebugControl = NULL;

	// Get the address of NtSystemDebugControl
    if (!(pNtSystemDebugControl = (fnNtSystemDebugControl)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtSystemDebugControl"))) {
        printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    // STATUS_DEBUGGER_INACTIVE: 0xC0000354 - An attempt to do an operation on a debug port failed because the port is in the process of being deleted.
    if ((STATUS = pNtSystemDebugControl(SysDbgBreakPoint, NULL, NULL, NULL, NULL, NULL)) == 0xC0000354)
        return FALSE;

    return TRUE;
}
// Can add more debugging checks here below