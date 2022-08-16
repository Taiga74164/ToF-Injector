#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>
#include <string>
#include <thread>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#pragma comment(lib,"ntdll.lib")

#ifndef UNICODE
#define UNICODE
#endif

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define STATUS_SUCCESS    ((NTSTATUS)0x00000000L)

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2
#define ThreadQuerySetWin32StartAddress 9

static int num = 0;

typedef NTSTATUS(NTAPI* _NtQueryInformationThread)(
    HANDLE, 
    NTSTATUS, 
    PVOID, 
    ULONG, 
    PULONG);

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );

typedef NTSTATUS(NTAPI* _NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;
typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;
typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;
typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG                   NextEntryOffset;
    ULONG                   NumberOfThreads;
    LARGE_INTEGER           Reserved[3];
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           KernelTime;
    UNICODE_STRING          ImageName;
    ULONG                   BasePriority;
    HANDLE                  ProcessId;
    HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

PVOID GetLibraryProcAddress(LPCSTR LibraryName, LPCSTR ProcName);
bool CloseHandleName(const wchar_t* name);
uintptr_t PatternScan(void* module, const char* signature);
DWORD GetPID(std::string ProcessName);
uintptr_t GetModuleAddress(std::string module, DWORD pid);
DWORD GetThreadID(DWORD pid);
bool SuspendProcess(DWORD pid);
bool ResumeProcess(DWORD pid);
std::string RandomString(const size_t length);
std::string GetLastErrorAsString();
void Bedge(int ms);
void Patch(void* dst, const char* src, unsigned int size, HANDLE hProcess);
void Nop(void* dst, unsigned int size, HANDLE hProcess);
