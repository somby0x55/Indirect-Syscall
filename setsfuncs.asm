
.data
	variableSSN DWORD 0h
	variableSyscall QWORD 0h

.code

	setSSN proc
		mov variableSSN, ecx
		ret
	setSSN endp

	setSyscall proc
		mov variableSyscall, rcx
		ret
	setSyscall endp

	patchedFunction proc
		mov r10, rcx
		mov eax, variableSSN
		jmp qword ptr variableSyscall
		ret
	patchedFunction endp

end
