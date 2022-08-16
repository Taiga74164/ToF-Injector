#pragma once
#include <LoadLibrary.h>
#include <Utils.h>

static bool injected = false;
void Inject(HANDLE hProcess, std::string dllname)
{
    std::string buffer;
    buffer.reserve(GetCurrentDirectoryA(0, nullptr));
    ZeroMemory(buffer.data(), buffer.capacity());
    GetCurrentDirectoryA(buffer.capacity(), buffer.data());

    std::string DLLPath = buffer.c_str() + std::string("\\" + dllname);
    if (GetFileAttributesA(DLLPath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        printf("DLL not found: %s\n", dllname.c_str());
        return;
    }   

    LPVOID pPath = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pPath)
    {
        DWORD code = GetLastError();
        printf("VirtualAllocEx failed\n");
        return;
    }

    WriteProcessMemory(hProcess, pPath, DLLPath.data(), DLLPath.length(), nullptr);

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pPath, 0, nullptr);
    if (!hThread)
    {
        printf("CreateRemoteThread failed");
        return;
    }
    else
        injected = true;

    WaitForSingleObject(hThread, -1);
    VirtualFreeEx(hProcess, pPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    
    if (injected)
        printf("Injected: %s\n", dllname.c_str());
}