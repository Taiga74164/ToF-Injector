#include <Utils.h>
#include <Config.h>
#include <LoadLibrary.h>
#ifdef MANUAL_MAP
#include "ManualMap.h"
#endif

#define ThreadQuerySetWin32StartAddress 9

bool SuspendProtection(HANDLE hProcess, DWORD pid, uintptr_t protAddr)
{
    if (pid == 0 || protAddr == 0)
        return false;

    THREADENTRY32 te32{};
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    te32.dwSize = sizeof(te32);
    for (Thread32First(hThreadSnap, &te32); Thread32Next(hThreadSnap, &te32);)
    {
        if (te32.th32OwnerProcessID == pid)
        {
            PVOID threadInfo;
            ULONG retLen;
            auto NtQueryInformationThread = (_NtQueryInformationThread)GetLibraryProcAddress("ntdll.dll", "NtQueryInformationThread");
            if (NtQueryInformationThread == nullptr)
                return false;

            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
            NTSTATUS ntqiRet = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &threadInfo, sizeof(PVOID), &retLen);

            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(hProcess, (LPCVOID)threadInfo, &mbi, sizeof(mbi)))
            {
                auto baseAddress = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
                // LMAO very scuffed but it works 
                if (baseAddress == protAddr)
                {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                    return true;
                }
            }
        }
    }
    CloseHandle(hThreadSnap);
    return false;
}

int main()
{
    SetConsoleTitleA("Taiga74164");
    const auto config = LoadConfig();

    printf("Waiting for QRSL.exe\n");
    printf("=========================================\n");
    //print the Hotkeys for Manual Inject
    printf("[F2]  Manual Inject: %s\n", config.manualDllPath1.c_str());
    printf("[F3]  Manual Inject: %s\n", config.manualDllPath2.c_str());
    printf("=========================================\n");

    bool isInjected = false;
    while (true)
    {
        HWND hwnd = nullptr;
        while (!(hwnd = FindWindowA("UnrealWindow", nullptr)))
        {
            printf("Game not found!\n");
            isInjected = false;
            Bedge(1000);
        }
        
        DWORD dwProcID;
        while (!(GetWindowThreadProcessId(hwnd, &dwProcID)) || dwProcID == NULL)
        {
            printf("Unable to get process id!\n");
            Bedge(1000);
        }

        const auto handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcID);

        // Restore bytes of these hooked function
        Patch(GetLibraryProcAddress("ntdll.dll", "LdrInitializeThunk"), "\x40\x53\x48\x83\xEC\x20", 6, handle);
        Patch(GetLibraryProcAddress("ntdll.dll", "NtQueryAttributesFile"), "\x4C\x8B\xD1\xB8\x3D\x00\x00\x00", 8, handle);

        const auto QRSL_es = GetModuleAddress("QRSL_es.dll", dwProcID);
        if (!QRSL_es)
        {
            printf("QRSL_es.dll not found!\n");
            return 0;
        }

        if (SuspendProtection(handle, dwProcID, QRSL_es))
        {
            if (!isInjected)
            {
                Inject(handle, config.autoDllPath1); // Auto1 field
                Inject(handle, config.autoDllPath2); // Auto2 field
                isInjected = true;
            }

            if (GetAsyncKeyState(VK_F2) & 1)
                Inject(handle, config.manualDllPath1);

            if (GetAsyncKeyState(VK_F3) & 1)
                Inject(handle, config.manualDllPath2);
        }

        Bedge(20);
    }

    TerminateProcess((HANDLE)-1, 0);
    return 0;
}
