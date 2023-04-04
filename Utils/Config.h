#pragma once

#include <INIReader.h>

struct Config
{
    std::string autoDllPath1;
    std::string autoDllPath2;
    std::string manualDllPath1;
    std::string manualDllPath2;
};

bool WriteConfig(const Config& config);
Config LoadConfig();