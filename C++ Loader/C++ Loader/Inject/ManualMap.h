#pragma once
#include "../Main.h"
#include "XORSTRING.h"
#include "WinAPI.h"
#include <tchar.h>
class CInjection {
public:
	DWORD GetProcessIdByName(LPCTSTR name);
private:
	std::vector<std::string> m_processList;
	std::string sDecrypted;
}; extern CInjection g_Injection;

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);

typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, DWORD, PVOID);

typedef struct _MANUAL_INJECT
{
	PVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;
}MANUAL_INJECT, * PMANUAL_INJECT;


class manualmap
{
public:
	int manualmapmain(const char* proccessname, const char* dllname);
private:
	int map(unsigned int pid, LPCSTR dllname, LPCSTR exename);
	unsigned int GetProcessPID(const char* process_name);
	bool LoadProcess(const char* procName);
private:
	HANDLE hProcess = NULL;
	DWORD dwProcessId = NULL;
	bool processOk = false;
	unsigned int PID;
};

extern manualmap* manual_map;
//-----------------------------------------------------
// Coded by sarta! Free c++ loader source + web files
// https://github.com/sartachzym/C++-Cheat-Loader-CSGO-1.0/
// Copyright © sarta 2020
// Licensed under a MIT license
// Read the terms of the license here
// https://github.com/sartachzym/C++-Cheat-Loader-CSGO-1.0/blob/master/LICENSE
// Discord: SARTA THE STARCOPYRIGHT#2012
//-----------------------------------------------------