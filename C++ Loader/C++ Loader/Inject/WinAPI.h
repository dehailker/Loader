#pragma once
#include "../Main.h"
#include <bcrypt.h>
DWORD getKernel32Address();
PVOID get_proc_address(DWORD module, const char* proc_name);
PVOID callWinAPIFunction(LPCTSTR pszModule, LPCTSTR pszFunction, int arguments, ...);
#define STATUS_BUFFER_OVERFLOW
LPCTSTR decode(const char* pszSource);

int MessageBoxHidden(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
void GdiplusShutdownHidden(ULONG_PTR token);
void GetPrivateProfileStringHidden(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpDefault, LPSTR lpReturnedString, DWORD nSize, LPCSTR lpFileName);
void InitCommonControlsHidden();
void GetModuleFileNameHidden(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
void GetWindowRectHidden(HWND hWnd, LPRECT lpRect);
void WritePrivateProfileStringHidden(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpString, LPCSTR lpFileName);
HWND GetDesktopWindowHidden();
HFONT CreateFontHidden(int cHeight, int cWidth, int cEscapement, int cOrientation, int cWeight, DWORD bItalic, DWORD bUnderline, DWORD bStrikeOut, DWORD iCharSet, DWORD iOutPrecision, DWORD iClipPrecision, DWORD iQuality, DWORD iPitchAndFamily, LPCSTR pszFaceName);
void SendMessageHidden(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
HWND CreateWindowExAHidden(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
void GetDlgItemTextHidden(HWND hDlg, int nIDDlgItem, LPSTR lpString, int cchMax);
LRESULT SendDlgItemMessageHidden(HWND hDlg, int nIDDlgItem, UINT Msg, WPARAM wParam, LPARAM lParam);
HICON LoadIconHidden(HINSTANCE hInstance, LPCSTR lpIconName);
HCURSOR LoadCursorHidden(HINSTANCE hInstance, LPCSTR lpCursorName);
HMODULE GetModuleHandleHidden(LPCSTR lpModuleName);
ATOM RegisterClassExHidden(const WNDCLASSEXA* lpwcx);
void FormatMessageHidden(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list* Arguments);
DWORD GetLastErrorHidden();
int WSAStartupHidden(WORD wVersionRequested, LPWSADATA lpWSAData);
void ExitProcessHidden(UINT uExitCode);
int getaddrinfoHidden(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult);
SOCKET socketHidden(int af, int type, int protocol);
void freeaddrinfoHidden(PADDRINFOA pAddrInfo);
int sendHidden(SOCKET s, const char FAR* buf, int len, int flags);
int closesocketHidden(SOCKET s);
int WSACleanupHidden();
int recvHidden(SOCKET s, char FAR* buf, int len, int flags);
int connectHidden(SOCKET s, const struct sockaddr FAR* name, int namelen);
HANDLE CreateToolhelp32SnapshotHidden(DWORD dwFlags, DWORD th32ProcessID);
BOOL Process32FirstHidden(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
BOOL Process32NextHidden(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
BOOL CloseHandleHidden(HANDLE hObject);
HANDLE OpenProcessHidden(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
LPVOID VirtualAllocExHidden(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL Module32FirstHidden(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
BOOL Module32NextHidden(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
BOOL WriteProcessMemoryHidden(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
SIZE_T VirtualQueryExHidden(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
BOOL VirtualProtectExHidden(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
BOOL FlushInstructionCacheHidden(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize);
BOOL VirtualProtectHidden(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
HANDLE CreateRemoteThreadHidden(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DWORD WaitForSingleObjectHidden(HANDLE hHandle, DWORD dwMilliseconds);
HGDIOBJ SelectObjectHidden(HDC hdc, HGDIOBJ h);
HBRUSH CreateSolidBrushHidden(COLORREF color);
COLORREF SetTextColorHidden(HDC hdc, COLORREF color);
int FillRectHidden(HDC hDC, CONST RECT* lprc, HBRUSH hbr);
int FrameRectHidden(HDC hDC, CONST RECT* lprc, HBRUSH hbr);
BOOL GlobalUnlockHidden(HGLOBAL hMem);
HGLOBAL GlobalFreeHidden(HGLOBAL hMem);
HRSRC FindResourceHidden(HMODULE hModule, LPCSTR lpName, LPCSTR lpType);
DWORD SizeofResourceHidden(HMODULE hModule, HRSRC hResInfo);
HGLOBAL LoadResourceHidden(HMODULE hModule, HRSRC hResInfo);
LPVOID LockResourceHidden(HGLOBAL hResData);
HGLOBAL GlobalAllocHidden(UINT uFlags, SIZE_T dwBytes);
LPVOID GlobalLockHidden(HGLOBAL hMem);
HRESULT CreateStreamOnHGlobalHidden(HGLOBAL hGlobal, BOOL fDeleteOnRelease, LPSTREAM FAR* ppstm);
int SetBkModeHidden(HDC hdc, int mode);
int GetWindowTextLengthHidden(HWND hWnd);
int GetWindowTextHidden(HWND hWnd, LPSTR lpString, int nMaxCount);
int DrawTextHidden(HDC hdc, LPCSTR lpchText, int cchText, LPRECT lprc, UINT format);
HPEN CreatePenHidden(int iStyle, int cWidth, COLORREF color);
BOOL RoundRectHidden(HDC hdc, int left, int top, int right, int bottom, int width, int height);
BOOL DeleteObjectHidden(HGDIOBJ ho);
BOOL GetMessageHidden(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
BOOL TranslateMessageHidden(CONST MSG* lpMsg);
LRESULT DispatchMessageHidden(CONST MSG* lpMsg);
BOOL MoveToExHidden(HDC hdc, int x, int y, LPPOINT lppt);
BOOL LineToHidden(HDC hdc, int x, int y);
HDC BeginPaintHidden(HWND hWnd, LPPAINTSTRUCT lpPaint);
BOOL EndPaintHidden(HWND hWnd, CONST PAINTSTRUCT* lpPaint);
BOOL SetDlgItemTextHidden(HWND hDlg, int nIDDlgItem, LPCSTR lpString);
void PostQuitMessageHidden(int nExitCode);
LRESULT DefWindowProcHidden(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
BOOL PostMessageHidden(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
BOOL GetUserNameHidden(LPTSTR lpBuffer, LPDWORD lpnSize);
BOOL OpenProcessTokenHidden(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
HANDLE GetCurrentProcessHidden(VOID);
BOOL LookupprivilegeValueHidden(LPCTSTR lpSystemname, LPCTSTR lpname, PLUID lpLuid);
BOOL AdjustTokenPrivilegesHidden(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
BOOL HeapFreeHidden(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
HANDLE GetProcessHeapHidden(VOID);
VOID FreeLibraryAndExitThreadHidden(HMODULE hModule, DWORD dwExitCode);
HANDLE CreateThreadHidden(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
COLORREF SetBkColorHidden(HDC hdc, COLORREF crColor);
COLORREF SetDCBrushColorHidden(HDC, COLORREF);
HGDIOBJ GetStockObjectHidden(int fnObject);
BOOL ShowWindowHidden(HWND hWnd, int nCmdShow);
HBRUSH CreatePatternBrushHidden(HBITMAP hBmp);
HBITMAP LoadBitmapHidden(HINSTANCE hInstance, LPCTSTR lpBitmapName);
NTSTATUS NtQueryInformationProcessHidden(HANDLE ProcessHandle, UINT ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
NTSTATUS NtSetInformationThreadHidden(HANDLE ThreadHandle, UINT ThreadInformationClass, PVOID pMem, ULONG ulBuf);
HANDLE GetCurrentThreadHidden(VOID);
VOID GetStartupInfoHidden(LPSTARTUPINFO lpStartupInfo);
BOOL CreateProcessHidden(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
LPTSTR GetCommandLineHidden(VOID);
BOOL ContinueDebugEventHidden(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus);
BOOL WaitForDebugEventHidden(_Out_ LPDEBUG_EVENT lpDebugEvent, _In_ DWORD dwMilliseconds);
LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilterHidden(_In_opt_ LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
ATOM RegisterClassHidden(const WNDCLASS* lpWndClass);
BOOL IsDialogMessageHidden(_In_ HWND hDlg, _In_ LPMSG lpMsg);
BOOL UpdateWindowHidden(_In_ HWND hWnd);
BOOL GetCurrentHwProfileHidden(_Out_ LPHW_PROFILE_INFOA lpHwProfileInfo);
ULONG GetAdaptersAddressesHidden(_In_ ULONG Family, _In_ ULONG Flags, _Reserved_ PVOID Reserved, _Out_writes_bytes_opt_(*SizePointer) PIP_ADAPTER_ADDRESSES AdapterAddresses, _Inout_ PULONG SizePointer);
BOOL PathFileExistsHidden(LPCTSTR pszPath);
HRESULT ObtainUserAgentStringHidden(DWORD dwOption, char* pcszUAOut, DWORD* cbSize);
//-----------------------------------------------------
// Coded by sarta! Free c++ loader source + web files
// https://github.com/sartachzym/C++-Cheat-Loader-CSGO-1.0/
// Copyright © sarta 2020
// Licensed under a MIT license
// Read the terms of the license here
// https://github.com/sartachzym/C++-Cheat-Loader-CSGO-1.0/blob/master/LICENSE
// Discord: SARTA THE STARCOPYRIGHT#2012
//-----------------------------------------------------