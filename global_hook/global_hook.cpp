#include <Windows.h>
#define _CRT_SECURE_NO_WARNINGS

#define _T(X) L ## X
#define jmp 0xe9
#define CODE_LENGTH 5
BYTE oldCode[CODE_LENGTH];
BYTE newCode[CODE_LENGTH];

HANDLE hProcess;
HINSTANCE hInst;


typedef int(WINAPI *ptrMessageBoxW)(
	HWND    hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT    uType
	);
ptrMessageBoxW originMsgBox;


void hookOff();
void hookOn();
void GetAdr();

int WINAPI hookedMessageBoxW(
	HWND    hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT    uType
) {
	hookOff();
	int ret = MessageBoxW(hWnd, _T("Hooked"), lpCaption, uType);
	hookOn();
	return ret;
};
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

void hookOn() {
	if (hProcess == NULL)return;
	DWORD dwTmp;
	DWORD dwOldProtect;
	SIZE_T writedByte;

	VirtualProtectEx(hProcess, originMsgBox, CODE_LENGTH, PAGE_READWRITE, &dwOldProtect);
	WriteProcessMemory(hProcess, originMsgBox, newCode, CODE_LENGTH, &writedByte);
	if (writedByte == 0)return;

	VirtualProtectEx(hProcess, originMsgBox, CODE_LENGTH, dwOldProtect, &dwTmp);
}

void hookOff() {
	if (hProcess == NULL)return;
	DWORD dwTmp;
	DWORD dwOldProtect;
	SIZE_T writedByte;

	VirtualProtectEx(hProcess, originMsgBox, CODE_LENGTH, PAGE_READWRITE, &dwOldProtect);
	WriteProcessMemory(hProcess, originMsgBox, oldCode, CODE_LENGTH, &writedByte);


	VirtualProtectEx(hProcess, originMsgBox, CODE_LENGTH, dwOldProtect, &dwTmp);
}

void GetAdr() {
	HMODULE hModule = LoadLibrary(L"user32.dll");
	if (hModule == NULL) {
		return;
	}
	originMsgBox = (ptrMessageBoxW)GetProcAddress(hModule, "MessageBoxW");
	if (originMsgBox == NULL) {
		return;
	}
	memcpy(oldCode, originMsgBox, 5);
	/*_asm {
	mov esi, originMsgBox
	lea edi, oldCode
	cld
	movsd
	movsb

	}*/
	newCode[0] = jmp;
	_asm
	{
		lea eax, hookedMessageBoxW
		mov ebx, originMsgBox
		sub eax, ebx
		sub eax, CODE_LENGTH
		mov dword ptr[newCode + 1], eax
	}/*
	 jmp dest
	 dest = myAddress - originAddress - 5
	 */

	hookOn();

}


HHOOK hHook;



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
		hProcess = GetCurrentProcess();
		GetAdr();
		MessageBox(NULL, L"Load DLL!", L"PROCESS_ATTACH", MB_OK);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

	return true;



}