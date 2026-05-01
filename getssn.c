#pragma once
#include <stdio.h>
#include <Windows.h>

void* patchFunc(char* targetDll, char* funcName) {

	HMODULE hDll = GetModuleHandleA(targetDll);
	UINT_PTR pFunc = (UINT_PTR)GetProcAddress(hDll, funcName);
	DWORD funcSSN = ((PBYTE)(pFunc + 4))[0];
	if (funcSSN == 0) {
		printf("\n\n(!) Error getting SSN for %s: %lu\n", funcName, GetLastError());
		return;
	}
	printf("\n(+) Found SSN successfully for %s: 0x%x", funcName, funcSSN);
	setFunction(funcSSN);

	return;
}
