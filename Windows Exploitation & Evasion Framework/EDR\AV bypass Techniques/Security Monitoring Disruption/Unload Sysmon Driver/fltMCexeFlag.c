#include "stdafx.h"
#include <Windows.h>
#include <fltuser.h>

#pragma comment(lib,"FltLib.lib")

/*
Author: Osanda Malith Jayathissa (@OsandaMalith)
*/

typedef NTSTATUS(WINAPI *_RtlAdjustPrivilege)(
	ULONG Privilege, BOOL Enable,
	BOOL CurrentThread, PULONG Enabled);

int _tmain(int argc, _TCHAR* argv[]) {
	
	ULONG t;
	HRESULT unload;
	LPCWSTR driver = L"SysmonDrv";

	_RtlAdjustPrivilege RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(GetModuleHandle(L"ntdll"), "RtlAdjustPrivilege");
	
	RtlAdjustPrivilege(012, TRUE, FALSE, &t);

	unload = FilterUnload(driver);

	wprintf(L"%ls", unload == S_OK ? 
		L"Minifilter Successfully Unloaded" : 
		L"An Error Occured. Check Privs."
	);
    
	return 0;
}
