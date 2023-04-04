#pragma once

#include <Windows.h>
#include <iostream>
#include <string>

void Inject(HANDLE hProcess, const std::string& dllName);