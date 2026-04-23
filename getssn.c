#pragma once
#include <stdio.h>
#include <Windows.h>


void* GetSSN(HMODULE hNtdll, char* targetFuncName, PDWORD TargetFuncSSN) {

    UINT_PTR pTargetFunc = (UINT_PTR)GetProcAddress(hNtdll, targetFuncName);
    *TargetFuncSSN = ((PBYTE)(pTargetFunc + 4))[0];
    if (TargetFuncSSN == 0) {
        printf("(!) Error getting SSN for %s: %lu\n", targetFuncName, GetLastError());
        return 1;
    }

    return;
}
