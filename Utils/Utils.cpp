#include <Utils.h>

PVOID GetLibraryProcAddress(LPCSTR LibraryName, LPCSTR ProcName)
{
    auto hModule = GetModuleHandleA(LibraryName);
    if (hModule == NULL)
        return nullptr;
    return GetProcAddress(hModule, ProcName);
}

bool CloseHandleName(const wchar_t* name)
{
    _NtQuerySystemInformation NtQuerySystemInformation =
        (_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
    _NtDuplicateObject NtDuplicateObject =
        (_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
    _NtQueryObject NtQueryObject =
        (_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");
    NTSTATUS status;

    ULONG handleInfoSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

    ULONG pid = 0;
    HANDLE processHandle = GetCurrentProcess();
    ULONG i;

    /* NtQuerySystemInformation won't give us the correct buffer size,
       so we guess by doubling the buffer size. */
    while ((status = NtQuerySystemInformation(
        SystemHandleInformation,
        handleInfo,
        handleInfoSize,
        NULL
    )) == STATUS_INFO_LENGTH_MISMATCH)
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

    /* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */
    if (!NT_SUCCESS(status))
    {
        printf("NtQuerySystemInformation failed!\n");
        return false;
    }

    bool closed = false;
    for (i = 0; i < handleInfo->HandleCount; i++)
    {
        if (closed)
            break;

        SYSTEM_HANDLE handle = handleInfo->Handles[i];
        HANDLE dupHandle = NULL;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        PVOID objectNameInfo;
        UNICODE_STRING objectName;
        ULONG returnLength;

        /* Duplicate the handle so we can query it. */
        if (!NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0)))
            continue;

        /* Query the object type. */
        objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
        if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL)))
        {
            CloseHandle(dupHandle);
            continue;
        }

        /* Query the object name (unless it has an access of
           0x0012019f, on which NtQueryObject could hang. */
        if (handle.GrantedAccess == 0x0012019f)
        {
            free(objectTypeInfo);
            CloseHandle(dupHandle);
            continue;
        }

        objectNameInfo = malloc(0x1000);
        if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength)))
        {
            /* Reallocate the buffer and try again. */
            objectNameInfo = realloc(objectNameInfo, returnLength);
            if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL)))
            {
                free(objectTypeInfo);
                free(objectNameInfo);
                CloseHandle(dupHandle);
                continue;
            }
        }

        /* Cast our buffer into an UNICODE_STRING. */
        objectName = *(PUNICODE_STRING)objectNameInfo;

        /* Print the information! */
        if (objectName.Length && lstrcmpiW(objectName.Buffer, name) == 0)
        {
            CloseHandle((HANDLE)handle.Handle);
            closed = true;
        }

        free(objectTypeInfo);
        free(objectNameInfo);
        CloseHandle(dupHandle);

    }

    free(handleInfo);
    CloseHandle(processHandle);
    return closed;
}

uintptr_t PatternScan(void* module, const char* signature)
{
    static auto pattern_to_byte = [](const char* pattern)
    {
        auto bytes = std::vector<int>{};
        auto start = const_cast<char*>(pattern);
        auto end = const_cast<char*>(pattern) + strlen(pattern);

        for (auto current = start; current < end; ++current)
        {
            if (*current == '?')
            {
                ++current;
                if (*current == '?')
                    ++current;
                bytes.push_back(-1);
            }
            else
            {
                bytes.push_back(strtoul(current, &current, 16));
            }
        }
        return bytes;
    };

    auto dosHeader = (PIMAGE_DOS_HEADER)module;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)module + dosHeader->e_lfanew);
    auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    auto patternBytes = pattern_to_byte(signature);
    auto scanBytes = reinterpret_cast<std::uint8_t*>(module);
    auto s = patternBytes.size();
    auto d = patternBytes.data();

    for (auto i = 0ul; i < sizeOfImage - s; ++i)
    {
        bool found = true;
        for (auto j = 0ul; j < s; ++j)
        {
            if (scanBytes[i + j] != d[j] && d[j] != -1)
            {
                found = false;
                break;
            }
        }
        if (found)
        {
            return (uintptr_t)&scanBytes[i];
        }
    }
    return 0;
}

DWORD GetPID(std::string ProcessName)
{
    DWORD pid = 0;
    PROCESSENTRY32 pe32{};
    HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    for (Process32First(hProcSnap, &pe32); Process32Next(hProcSnap, &pe32);)
    {
        pe32.dwSize = sizeof(pe32);
        if (pe32.szExeFile == ProcessName)
        {
            pid = pe32.th32ProcessID;
            break;
        }
    }
    CloseHandle(hProcSnap);
    return pid;
}

uintptr_t GetModuleAddress(std::string module, DWORD pid)
{
    uintptr_t modBaseAddr;
    MODULEENTRY32 mod32{};
    HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    mod32.dwSize = sizeof(mod32);
    for (Module32First(hModSnap, &mod32); Module32Next(hModSnap, &mod32);)
    {
        if (mod32.th32ProcessID != pid)
            continue;

        if (mod32.szModule == module)
        {
            modBaseAddr = (uintptr_t)mod32.modBaseAddr;
            break;
        }
    }
    CloseHandle(hModSnap);
    return modBaseAddr;
}

DWORD GetThreadID(DWORD pid)
{
    DWORD threadID;
    THREADENTRY32 te32{};
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    te32.dwSize = sizeof(te32);
    for (Thread32First(hThreadSnap, &te32); Thread32Next(hThreadSnap, &te32);)
    {
        if (te32.th32OwnerProcessID == pid)
        {
            threadID = te32.th32ThreadID;
            //printf("threadID: %d\n", te32.th32ThreadID);
        }
    }
    CloseHandle(hThreadSnap);
    return threadID;
}

bool SuspendProcess(DWORD pid)
{
    THREADENTRY32 te32{};
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    te32.dwSize = sizeof(te32);
    for (Thread32First(hThreadSnap, &te32); Thread32Next(hThreadSnap, &te32);)
    {
        if (te32.th32OwnerProcessID == pid)
        {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
            SuspendThread(hThread);
            CloseHandle(hThread);
        }
    }
    CloseHandle(hThreadSnap);
    return true;
}

bool ResumeProcess(DWORD pid)
{
    THREADENTRY32 te32{};
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    te32.dwSize = sizeof(te32);
    for (Thread32First(hThreadSnap, &te32); Thread32Next(hThreadSnap, &te32);)
    {
        if (te32.th32OwnerProcessID == pid)
        {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
            ResumeThread(hThread);
            CloseHandle(hThread);
        }
    }
    CloseHandle(hThreadSnap);
    return true;
}

std::string RandomString(const size_t length)
{
    std::string Title;
    static const char bet[] = { "ABCDEFGHIJKLMNOPQRSTUVWXYabcdefghijklmnopqrstuvwxyzZ1234567890" };
    srand((unsigned)time(NULL) * 5);
    for (int i = 0; i < length; ++i)
        Title += bet[rand() % (sizeof(bet) - 1)];
    return Title;
}
std::string GetLastErrorAsString()
{
    DWORD code = GetLastError();
    LPSTR buf = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buf, 0, NULL);
    std::string ret = buf;
    LocalFree(buf);
    return ret;
}
void Bedge(int ms)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}
void Patch(void* dst, const char* src, unsigned int size, HANDLE hProcess)
{
    DWORD oldprotect;
    VirtualProtectEx(hProcess, dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);
    WriteProcessMemory(hProcess, dst, src, size, nullptr);
    VirtualProtectEx(hProcess, dst, size, oldprotect, &oldprotect);
}
void Nop(void* dst, unsigned int size, HANDLE hProcess)
{
    BYTE* nopArray = new BYTE[size];
    memset(nopArray, 0x90, size);
    Patch(dst, (const char*)nopArray, size, hProcess);
    delete[] nopArray;
}
