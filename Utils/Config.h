#pragma once
#include <Utils.h>
#include <IniReader.h>

std::string DllPath1{};
std::string DllPath2{};
std::string DllPath3{};
std::string DllPath4{};
std::string DllPath5{};

bool WriteConfig(std::string DllPath1, std::string DllPath2, std::string DllPath3, std::string DllPath4, std::string DllPath5)
{
    HANDLE hFile = CreateFileA("config.ini", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Failed to create file\n");
        return false;
    }

    std::string content{};
    content = "[Settings]\n";
    content += "Auto1=" + DllPath1 + "\n";
    content += "Manual2=" + DllPath2 + "\n";
    content += "Manual3=" + DllPath3 + "\n";
    content += "Manual4=" + DllPath4 + "\n";
    content += "Manual5=" + DllPath5 + "\n";

    DWORD written = 0;
    WriteFile(hFile, content.data(), content.size(), &written, nullptr);
    CloseHandle(hFile);
}

void LoadConfig()
{
    if (GetFileAttributesA("config") != INVALID_FILE_ATTRIBUTES)
        DeleteFileA("config");

    INIReader reader("config.ini");
    if (reader.ParseError() != 0)
    {
        //
    }

    DllPath1 = reader.Get("Settings", "Auto1", "");
    DllPath2 = reader.Get("Settings", "Manual2", "");
    DllPath3 = reader.Get("Settings", "Manual3", "");
    DllPath4 = reader.Get("Settings", "Manual4", "");
    DllPath5 = reader.Get("Settings", "Manual5", "");
}