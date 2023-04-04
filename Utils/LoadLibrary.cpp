#include <LoadLibrary.h>

void Inject(HANDLE hProcess, const std::string& dllName)
{
    char buffer[MAX_PATH];
    if (!GetFullPathNameA(dllName.c_str(), MAX_PATH, buffer, nullptr))
    {
        std::cout << "GetFullPathNameA failed" << GetLastError() << std::endl;
        return;
    }

    if (GetFileAttributesA(buffer) == INVALID_FILE_ATTRIBUTES)
    {
        std::cout << "DLL not found: " << dllName << std::endl;
        return;
    }

    const auto pPath = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pPath)
    {
        std::cout << "VirtualAllocEx failed" << GetLastError() << std::endl;
        return;
    }

    if (!WriteProcessMemory(hProcess, pPath, buffer, strlen(buffer), nullptr))
    {
        std::cout << "WriteProcessMemory failed" << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pPath, 0, MEM_RELEASE);
        return;
    }

    const auto hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), pPath, 0, nullptr);
    if (!hThread)
    {
        std::cout << "CreateRemoteThread failed" << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pPath, 0, MEM_RELEASE);
        return;
    }

    WaitForSingleObject(hThread, -1);
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    std::cout << (exitCode == 0 ? "Failed to inject: " : "Injected: ") << dllName << std::endl;
    
    VirtualFreeEx(hProcess, pPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
}