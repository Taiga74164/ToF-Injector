#include <Utils.h>
#include <Config.h>
#include <LoadLibrary.h>
#ifdef MANUAL_MAP
#include "ManualMap.h"
#endif

static bool isInject = false;

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
            NTSTATUS ntqiRet = NtQueryInformationThread(hThread, 9, &threadInfo, sizeof(PVOID), &retLen);

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
    LoadConfig();

    std::string DLLName1 = DllPath1.substr(DllPath1.find_last_of("\\") + 1);
    std::string DLLName2 = DllPath2.substr(DllPath2.find_last_of("\\") + 1);
    std::string DLLName3 = DllPath3.substr(DllPath3.find_last_of("\\") + 1);
    std::string DLLName4 = DllPath4.substr(DllPath4.find_last_of("\\") + 1);
    std::string DLLName5 = DllPath5.substr(DllPath5.find_last_of("\\") + 1);

    printf("Waiting for QRSL.exe\n");
    printf("=========================================\n");
    //print the Hotkeys for Manual Inject
    printf("[F2]  Manual Inject: %s\n", DLLName2.c_str());
    printf("[F3]  Manual Inject: %s\n", DLLName3.c_str());
    printf("[F4]  Manual Inject: %s\n", DLLName4.c_str());
    printf("[F5]  Manual Inject: %s\n", DLLName5.c_str());
    printf("=========================================\n");

    DWORD ExitCode = STILL_ACTIVE;
    while (ExitCode == STILL_ACTIVE)
    {
        HWND hwnd = nullptr;
        while (!(hwnd = FindWindowA("UnrealWindow", nullptr)))
            Bedge(100);

        auto LdrInitializeThunk = GetLibraryProcAddress("ntdll.dll", "LdrInitializeThunk");
        if (!LdrInitializeThunk)
        {
            printf("LdrInitializeThunk not found!\n");
            return 0;
        }

        auto NtQueryAttributesFile = GetLibraryProcAddress("ntdll.dll", "NtQueryAttributesFile");
        if (!NtQueryAttributesFile)
        {
            printf("NtQueryAttributesFile not found!\n");
            return 0;
        }

        if (hwnd)
        {
            DWORD dwProcID;
            GetWindowThreadProcessId(hwnd, &dwProcID);
            if (dwProcID != NULL)
            {
                HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcID);

                // Restore bytes of these hooked function
                Patch(LdrInitializeThunk, "\x40\x53\x48\x83\xEC\x20", 6, handle);
                Patch(NtQueryAttributesFile, "\x4C\x8B\xD1\xB8\x3D\x00\x00\x00", 8, handle);

                auto QRSL_es = GetModuleAddress("QRSL_es.dll", dwProcID);
                if (!QRSL_es)
                {
                    printf("QRSL_es.dll not found!\n");
                    return 0;
                }

                if (SuspendProtection(handle, dwProcID, QRSL_es))
                {
                    if (!isInject)
                    {
                        Inject(handle, DLLName1.c_str()); // Auto1 field
                        isInject = true;
                    }

                    if (GetAsyncKeyState(VK_F2) & 1)
                        Inject(handle, DLLName2.c_str());

                    if (GetAsyncKeyState(VK_F3) & 1)
                        Inject(handle, DLLName3.c_str());

                    if (GetAsyncKeyState(VK_F4) & 1)
                        Inject(handle, DLLName4.c_str());

                    if (GetAsyncKeyState(VK_F5) & 1)
                        Inject(handle, DLLName5.c_str());
                }
                // Commented so you don't have to restart injector everytime the game closes
                //GetExitCodeProcess(handle, &ExitCode);
            }
        }
        Bedge(20);
    }

    TerminateProcess((HANDLE)-1, 0);
    return 0;
}
