#pragma once
#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <winsock2.h>
#include <security.h> // Include for EXTENDED_NAME_FORMAT
#include <iphlpapi.h> // Include for PIP_ADAPTER_ADDRESSES
#include <iostream>
#include <thread>
#include "ImGui/imgui.h"
#include "ImGui/imgui_impl_dx9.h"
#include <d3d9.h>
#include <d3dx9.h>

#pragma comment(lib,"d3dx9.lib")

#include "xorstr.h"
#include <windows.h>
#include <assert.h>
#include <tlhelp32.h>
#include <iostream>
#include <excpt.h>
#include <signal.h>
#include <shlwapi.h>
#include <windows.h>
#include <string>
#include <iostream>
#include <ostream>
#include <vector>
#include "Inject/ManualMap.h"
#include <Urlmon.h>
#include "sartaprotect.h"

#pragma comment(lib,"d3d9.lib")
#pragma comment(lib,"dxguid.lib")
#pragma comment(lib, "urlmon.lib")

#define NAME  LethalStr("c++ loader")
#define NAME_LOADER LethalStr("c++ loader")
#define WINDOW_WIDTH  500
#define WINDOW_HEIGHT 500
using namespace std;
inline IDirect3DDevice9*     g_D3DDevice9;
namespace ImGui {
	void Separator2(const char * label, ...);
}

extern IDirect3DTexture9* Logo;

#include <string>
#include <curl\curl.h> 
//#pragma comment(lib, "libcurl_a.lib")
//ATOM RegMyWindowClass(HINSTANCE, LPCTSTR);
static LPDIRECT3DDEVICE9        g_pd3dDevice = NULL;
static D3DPRESENT_PARAMETERS    g_d3dpp;
extern LRESULT ImGui_ImplDX9_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
//LRESULT CALLBACK sarta(HWND, UINT, WPARAM, LPARAM);
static char errorBuffer[CURL_ERROR_SIZE];
static string buffers;
BOOL IsAdministrator(VOID);
static int writer(char* data, size_t size, size_t nmemb, string* buffer)
{
	int result = 0;
	if (buffer != NULL)
	{
		buffer->append(data, size * nmemb);
		result = size * nmemb;
	}
	return result;
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
