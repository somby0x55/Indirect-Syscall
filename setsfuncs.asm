
.data
	variableSSN DWORD 0h

.code

	setFunction proc
		mov variableSSN, ecx
		ret
	setFunction endp

	patchedFunction proc
		mov r10, rcx
		mov eax, variableSSN
		syscall
		ret
	patchedFunction endp

end
