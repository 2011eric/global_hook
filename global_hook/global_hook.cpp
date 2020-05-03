#include <Windows.h>
HHOOK hHook;

void debugPrivilege() {
	HANDLE hToken;
	bool bRet = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
	if (bRet) {
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
	}
}

LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {
	return CallNextHookEx(hHook, nCode, wParam, lParam);
}
extern "C" __declspec(dllexport) bool HookOn(HMODULE hModule) {

	hHook = SetWindowsHookEx(WH_CBT, HookProc, hModule, 0);
	if (hHook == NULL) {
		MessageBox(NULL, L"SetWindowsHookEx", L"Error", MB_ICONERROR);
		return false;
	}
	else {
		MessageBox(NULL, L"SetWindowsHookEx", L"Success", MB_OK);
	}
	return true;
}


extern "C" __declspec(dllexport) bool HookOff() {
	bool ret = false;
	if (hHook) {
		ret = UnhookWindowsHookEx(hHook);
		if (!ret) {
			MessageBox(NULL, L"Unknown Hook", L"Error", MB_ICONERROR);
			return false;
		}
		return true;
	}
	return false;

}

BOOL APIENTRY DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	debugPrivilege();
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		
		MessageBox(NULL, L"Load DLL!", L"PROCESS_ATTACH", MB_OK);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

	return true;



}