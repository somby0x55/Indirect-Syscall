#pragma once
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

extern NTSTATUS NtOpenProcess(
	PHANDLE,
	ACCESS_MASK,
	POBJECT_ATTRIBUTES,
	CLIENT_ID
);

extern NTSTATUS NtAllocateVirtualMemory(
	HANDLE,
	PVOID,
	ULONG_PTR,
	PSIZE_T,
	ULONG,
	ULONG
);

extern NTSTATUS NtWriteVirtualMemory(
	HANDLE,
	PVOID,
	PVOID,
	SIZE_T,
	PSIZE_T
);

extern NTSTATUS NtCreateThreadEx(
	PHANDLE,
	ACCESS_MASK,
	POBJECT_ATTRIBUTES,
	HANDLE,
	PVOID,
	PVOID,
	ULONG,
	SIZE_T,
	SIZE_T,
	SIZE_T,
	VOID*
);
