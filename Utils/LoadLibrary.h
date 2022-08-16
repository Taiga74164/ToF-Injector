#pragma once
#include <Windows.h>
#include <string>

void Inject(HANDLE hProcess, std::string dllname);