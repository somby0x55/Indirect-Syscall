#pragma once
#include <stdio.h>
#include <Windows.h>

int patchFunc(char* targetDll, char* funcName) {

	UCHAR syscallOpcodes[2] = { 0x0F, 0x05 };
	HMODULE hDll = GetModuleHandleA(targetDll);
	UINT_PTR pFunc = (UINT_PTR)GetProcAddress(hDll, funcName);

	DWORD funcSSN = ((PBYTE)(pFunc + 4))[0];
	if (funcSSN == 0) {
		printf("\n\n(!) Error getting SSN for %s: %lu\n", funcName, GetLastError());
		return 1;
	}
	printf("\n(+) Found SSN successfully for %s: 0x%x", funcName, funcSSN);
	setSSN(funcSSN);

	UINT_PTR funcSyscall = (pFunc + 0x12);
	if (memcmp( funcSyscall, syscallOpcodes, sizeof(syscallOpcodes)) != 0) {
		printf("\n\n(!) Error getting syscall for %s: %lu\n", funcName, GetLastError());
		return 1;
	}
	printf("\n(+) Found syscall address successfully for %s: 0x%x", funcName, funcSyscall);
	setSyscall(funcSyscall);

	return 0;
}
