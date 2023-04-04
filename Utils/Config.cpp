#include "Config.h"
#include <iostream>
#include <fstream>

bool WriteConfig(const Config& config)
{
    std::ofstream file("config.ini");
    if (!file)
    {
        std::cout << "Failed to create file" << std::endl;
        return false;
    }
    
    file << "[Settings]\n";
    file << "Auto1 = " << config.autoDllPath1 << "\n";
    file << "Auto2 = " << config.autoDllPath2 << "\n";
    file << "Manual1 = " << config.manualDllPath1 << "\n";
    file << "Manual2 = " << config.manualDllPath2 << "\n";
    
    return true;
}

Config LoadConfig()
{
    const INIReader reader("config.ini");
    Config config;
    config.autoDllPath1 = reader.Get("Settings", "Auto1", "");
    config.autoDllPath2 = reader.Get("Settings", "Auto2", "");
    config.manualDllPath1 = reader.Get("Settings", "Manual1", "");
    config.manualDllPath2 = reader.Get("Settings", "Manual2", "");

    // Create config.ini if not present
    if (reader.ParseError() != 0)
        WriteConfig(config);

    return config;
}