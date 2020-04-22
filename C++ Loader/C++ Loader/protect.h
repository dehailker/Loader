#pragma once

#include "Main.h"
#include <stdlib.h>
#include "sartaprotect.h"

void DebugChecker()
{
	if (IsDebuggerPresent())
	{
		exit(1);
	}
}

bool IsProcessRun(const char* const processName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &pe);

	while (1) {
		if (strcmp(pe.szExeFile, processName) == 0) return true;
		if (!Process32Next(hSnapshot, &pe)) return false;
	}
}

void AntiDump()
{
	JUNK_CODE_ONE
		if (IsProcessRun("ollydbg.exe") || IsProcessRun("idaq64.exe") || IsProcessRun("HxD.exe") ||
			IsProcessRun("ResourceHacker.exe") || IsProcessRun("ProcessHacker.exe") || IsProcessRun("idaq32.exe")
			|| IsProcessRun("httpdebugger.exe") || IsProcessRun("windowrenamer.exe"))
		{
			exit(-1);
		}

	JUNK_CODE_ONE
}

BOOL IsAdministrator(VOID)
{
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;

	if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup))
	{
		return FALSE;
	}

	BOOL IsInAdminGroup = FALSE;

	if (!CheckTokenMembership(NULL, AdministratorsGroup, &IsInAdminGroup))
	{
		IsInAdminGroup = FALSE;
	}

	FreeSid(AdministratorsGroup);
	return IsInAdminGroup;
}

string build_date()
{
	return __DATE__;
}

string build_time()
{
	return __TIME__;
}
//-----------------------------------------------------
// Coded by sarta! Free c++ loader source + web files
// https://github.com/sartachzym/C++-Cheat-Loader-CSGO-1.0/
// Copyright © sarta 2020
// Licensed under a MIT license
// Read the terms of the license here
// https://github.com/sartachzym/C++-Cheat-Loader-CSGO-1.0/blob/master/LICENSE
// Discord: SARTA THE STARCOPYRIGHT#2012
//-----------------------------------------------------