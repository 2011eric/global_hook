// global_hook_loader.cpp: 定義主控台應用程式的進入點。
//

#include "stdafx.h"
#include <iostream>
#include <Windows.h>

typedef bool (__stdcall *DLLFUNC )(HMODULE);
#define DLLNAME "global_hook.dll"
int main()
{
	
		HMODULE hModule = LoadLibraryA(DLLNAME);
		if (hModule == NULL) {
			MessageBox(NULL, _T("Loader failed!"), _T("Error"), MB_ICONINFORMATION);
		}
		else {
			DLLFUNC ptrHookOn = (DLLFUNC)GetProcAddress(hModule, "HookOn");
			DLLFUNC ptrHookOff = (DLLFUNC)GetProcAddress(hModule, "HookOff");
			if (ptrHookOn == NULL || ptrHookOff == NULL) {
				MessageBox(NULL, _T("Function loading failed!"), _T("Error"), MB_ICONINFORMATION);
				return 1;
			}
			if (ptrHookOn(hModule)) {
				MessageBox(NULL, _T("HOOK Success!"), _T("OK"), MB_ICONINFORMATION);
			}
			else {
				MessageBox(NULL, _T("HOOK failed!"), _T("Error"), MB_ICONINFORMATION);
			}
			system("pause");
			ptrHookOff(hModule);
			MessageBox(NULL, _T("HOOK OFF!"), _T("OK"), MB_ICONINFORMATION);
		}


    return 0;
}

