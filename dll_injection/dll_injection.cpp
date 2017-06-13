#include "stdafx.h"
#include "thread.h"
#include "patch.h"

#define _CRT_SECURE_NO_WARNINGS

using namespace std;

#define MY_PROG			L"C:\\Users\\artem\\Documents\\visualstudio2015\\Projects\\MyProg\\Release\\MyProg.exe"
#define MY_DLL_x64		"C:\\Users\\artem\\Documents\\visualstudio2015\\Projects\\MyDLL\\x64\\Release\\MyDLL.dll"

#define KERNEL32		L"kernel32.dll"
#define TASK_MNGR		L"C:\\Windows\\System32\\Taskmgr.exe"
#define SIZE 16

unsigned char loop[] = {
	0x90,		// loop:	nop
	0x90,		//			nop
	0x90,		//			nop
	0x90,		//			nop
	0x90,		//			nop
	0xEB, 0xF9 	//			jmp loop
};

unsigned char get_base_image[] = {
	0x65, 0x4C, 0x8B, 0x24, 0x25, 0x60, 0x00, 0x00, 0x00, // mov r12, gs:[0x60]		;peb
	0x4D, 0x8B, 0x64, 0x24, 0x10, 						  // mov r12, [r12 + 0x10]	;Peb --> ImageBaseAddress 
	0x4C, 0x89, 0x21,									  // mov [rcx], r12			;save in mem
	0xC3 };

unsigned char get_ldr_byte_code_x32[] = {
	0x64, 0xA1, 0x30, 0x00, 0x00, 0x00,	//  mov eax, fs:[0x30]  // PEB
	0x8B, 0x40, 0x0C,					//  mov eax, [eax + 0x0C] // PEB_LDR_DATA
	0x8B, 0x40, 0x1C,					//  mov eax, [eax + 0x1C] // InInitializationOrderModuleList
	0xC3 };								//  ret	

unsigned char get_base_adr_x64[] = {
	0x65, 0x4C, 0x8B, 0x24, 0x25, 0x60, 0x00, 0x00, 0x00, // mov r12, gs:[0x60]		;peb
	0x4D, 0x8B, 0x64, 0x24, 0x18,						  // mov r12, [r12 + 0x18]	;Peb --> LDR 
	0x4D, 0x8B, 0x64, 0x24, 0x20,						  // mov r12, [r12 + 0x20]	;Peb.Ldr.InMemoryOrderModuleList
	0x4D, 0x8B, 0x24, 0x24,								  // mov r12, [r12]			;2st entry
	0x4D, 0x8B, 0x24, 0x24,								  // mov r12, [r12]			;3nd entry
	0x4D, 0x8B, 0x64, 0x24, 0x20,						  // mov r12, [r12 + 0x20]	;kernel32.dll base address!
	0x4C, 0x89, 0x21,									  // mov [rcx], r12			;save in mem
	0xC3 };

unsigned char byte_code_myLoadLibrary[] = {
	0x53,						// push        rbx
	0x48, 0x83, 0xEC, 0x20,		// sub         rsp,20h
	0x48, 0x89, 0xCB,			// mov         rbx,rcx
	0x48, 0x83, 0xC1, 0x10,		// add         rcx,10h
	0xFF, 0x13,					// call        qword ptr [rbx] 
	0x48, 0x8B, 0x43, 0x08,		// mov         rax,qword ptr [rbx+8] 
	0x48, 0x83, 0xC4, 0x20,		// add         rsp,20h 
	0x5B,						// pop         rbx
	0xFF, 0xE0					// jmp         rax 
};

typedef struct code_info {
	unsigned char *code;
	SIZE_T code_size;
} code_info_t;

typedef struct arg_info {
	unsigned char *arg;
	SIZE_T arg_size;
} arg_info_t;

typedef struct InfoExe {
	void *entry;
	unsigned char *base;
	unsigned char *PE_header;
} exe_info_t;

typedef struct InfoThread {
	code_info_t code;
	arg_info_t arg;
	DWORD ret_val;
} thread_info_t;

typedef struct InfoPatch {
	exe_info_t exe;
	unsigned char initial_code[SIZE];
	CONTEXT context;
} patch_t;

typedef HMODULE(*LoadLibrary_t)(_In_ LPCSTR lpLibFileName);

typedef DWORD(*GetLastError_t)(VOID);

typedef struct shell_code {
	LoadLibrary_t LoadLibrary_info;
	GetLastError_t GetLastError_info;
	char my_dll_path[MAX_PATH];
} shell_code_info_t;

__declspec(noinline)
int myLoadLibrary(shell_code_info_t *s_info) {
	HMODULE hModule = s_info -> LoadLibrary_info(s_info -> my_dll_path);
	return s_info->GetLastError_info();
}
void error_msg_with_exit(char *msg) {
	printf("Problem with '%s'!", msg);
	exit(-1);
}
void print_DOS_PE_Optional_Headers(PIMAGE_DOS_HEADER DOS_header, PIMAGE_NT_HEADERS PE_header);
int make_patch(PROCESS_INFORMATION pi, patch_t *p_info);
int unmake_patch(PROCESS_INFORMATION pi, patch_t *p_info);
int executeRemoteThread(PROCESS_INFORMATION pi, thread_info_t *t_info);
void *findKernel32Address_x64(PROCESS_INFORMATION pi);

void *findKernel32Address_x64(PROCESS_INFORMATION pi) {
	void *Kernel32;
	thread_info_t t_info;
	t_info.code.code = get_base_adr_x64;
	t_info.code.code_size = sizeof(get_base_adr_x64);
	t_info.arg.arg = (unsigned char *)&Kernel32;
	t_info.arg.arg_size = sizeof(Kernel32);

	if (executeRemoteThread(pi, &t_info))
		error_msg_with_exit("executionRemoteThread(pi, &t_info) in findKernel32...");
	return Kernel32;
}

void print_DOS_PE_Optional_Headers(PIMAGE_DOS_HEADER DOS_header, PIMAGE_NT_HEADERS PE_header) {
	printf("DOS HEADER = %c%c 0x%x \n", (DOS_header -> e_magic) & 0xFF, ((DOS_header ->e_magic) >> 8) & 0xFF, DOS_header -> e_lfanew);
	DWORD signature = PE_header -> Signature;
	printf("PE HEADER = #%c%c%x%x# 0x%x machine=%s \n",
		signature & 0xFF,
		(signature >> 8) & 0xFF,
		(signature >> 16) & 0xFF,
		(signature >> 24) & 0xFF,
		PE_header -> FileHeader.Machine,
		PE_header -> FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER) ? "x86" : "x64");

	PVOID p_opt_header = (PVOID)(((LPBYTE)PE_header) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	
	if (PE_header -> FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32)) {
		PIMAGE_OPTIONAL_HEADER32 x86_p_opt_header = (PIMAGE_OPTIONAL_HEADER32)p_opt_header;
		printf("\tAddressOfEntryPoint = %u\n", x86_p_opt_header -> AddressOfEntryPoint);
		printf("\tBaseOfCode = %u\n", x86_p_opt_header -> BaseOfCode);
		printf("\tFileAlignment = %u\n", x86_p_opt_header -> FileAlignment);
		printf("\tSizeOfImage = %u\n", x86_p_opt_header -> SizeOfImage);
	}
	else {
		PIMAGE_OPTIONAL_HEADER64 x64_p_opt_header = (PIMAGE_OPTIONAL_HEADER64)p_opt_header;
		printf("\tAddressOfEntryPoint = %u\n", x64_p_opt_header -> AddressOfEntryPoint);
		printf("\tBaseOfCode = %u\n", x64_p_opt_header -> BaseOfCode);
		printf("\tFileAlignment = %u\n", x64_p_opt_header -> FileAlignment);
		printf("\tSizeOfImage = %u\n", x64_p_opt_header -> SizeOfImage);
	}
	return;
}

int make_patch(PROCESS_INFORMATION pi, patch_t *p_info) {

	ULONG_PTR base;
	thread_info_t t_info;
	HANDLE hProcess = pi.hProcess;
	IMAGE_DOS_HEADER DOS_header;
	SIZE_T result = 0;

	//Initialize thread information
	t_info.code.code = get_base_image;
	t_info.code.code_size = sizeof(get_base_image);
	t_info.arg.arg_size = sizeof(base);
	t_info.arg.arg = (unsigned char *)&base;

	if (executeRemoteThread(pi, &t_info)) 
		error_msg_with_exit("executionRemoteThread");

	ReadProcessMemory(hProcess, (LPCVOID)base, &DOS_header, sizeof(IMAGE_DOS_HEADER), &result);
	if (result < sizeof(IMAGE_DOS_HEADER)) 
		error_msg_with_exit("result < sizeof(IMAGE_DOS_HEADER)");

	unsigned char *p_PE_header = (unsigned char *)(base + DOS_header.e_lfanew);
	(p_info -> exe).base = (unsigned char *)base;
	(p_info -> exe).PE_header = p_PE_header;

	result = 0;
	IMAGE_NT_HEADERS64 PE_Header;
	ReadProcessMemory(hProcess, p_PE_header, &PE_Header, sizeof(IMAGE_NT_HEADERS64), &result);
	if (result < sizeof(IMAGE_NT_HEADERS64))
		error_msg_with_exit("result < sizeof(IMAGE_NT_HEADERS64)");

	print_DOS_PE_Optional_Headers((PIMAGE_DOS_HEADER)(&DOS_header),(PIMAGE_NT_HEADERS)(&PE_Header));

	void *proc_entry_addr = NULL;
	SIZE_T offset = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

	if (PE_Header.FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32)) {
		printf("blabla");
		//entry_addr = (void *)(PE_Header.OptionalHeader.AddressOfEntryPoint + base);
		proc_entry_addr = (void *)((((PIMAGE_OPTIONAL_HEADER32)((unsigned char *)(&PE_Header) + offset)) ->AddressOfEntryPoint) + base);
	}
	else {
		//entry_addr = (void *)(PE_Header.OptionalHeader.AddressOfEntryPoint + base);
		proc_entry_addr = (void *)((((PIMAGE_OPTIONAL_HEADER64)((unsigned char *)(&PE_Header) + offset))->AddressOfEntryPoint) + base);
	}

	(p_info -> exe).entry = proc_entry_addr;
	(p_info -> context).ContextFlags = CONTEXT_FULL;

	result = 0;
	ReadProcessMemory(hProcess, proc_entry_addr, p_info -> initial_code, sizeof(loop), &result);
	if (result < sizeof(loop))
		error_msg_with_exit("result < sizeof(loop) in (ReadProcessMemory)");

	result = 0;
	WriteProcessMemory(hProcess, proc_entry_addr, loop, sizeof(loop), &result);
	if (result < sizeof(loop))
		error_msg_with_exit("result < sizeof(loop) in (WriteProcessMemory)");

	if (!GetThreadContext(pi.hThread, &(p_info->context)))
		error_msg_with_exit("GetThreadContext in make_patch");

	return 0;
}

int unmake_patch(PROCESS_INFORMATION pi, patch_t *p_info) {
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(pi.hThread, &context))
		error_msg_with_exit("GetThreadContext(pi.hThread, &context) in unmake_patch");

	context.ContextFlags = CONTEXT_FULL;
	context.Rip = (DWORD64)((p_info -> exe).entry);

	if (!SetThreadContext(pi.hThread, &context));
	SIZE_T result = 0;
	WriteProcessMemory(pi.hProcess, (p_info->exe).entry, p_info -> initial_code, sizeof(loop), &result);
	if (result < sizeof(loop))
		error_msg_with_exit("result < sizeof(loop) in unmake_patch");

	return 0;
}

int executeRemoteThread(PROCESS_INFORMATION pi, thread_info_t *t_info) {
	HANDLE hProcess = pi.hProcess;
	SIZE_T result = 0;

	//Allocate memory in remote process
	LPVOID p_remote_code = VirtualAllocEx(hProcess, NULL, (t_info -> code).code_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (p_remote_code == NULL)
		error_msg_with_exit("p_remote_code == NULL in executionRemoteThread");

	//Write code to memory
	WriteProcessMemory(hProcess, p_remote_code, (t_info -> code).code, (t_info -> code).code_size, &result);
	if (result < (t_info -> code).code_size)
		error_msg_with_exit("result < (t_info->code).code_size in executionRemoteThread");

	//Allocate memory in remote process
	LPVOID p_remote_arg = VirtualAllocEx(hProcess, NULL, (t_info -> arg).arg_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (p_remote_arg == NULL)
		error_msg_with_exit("p_remote_arg == NULL in executionRemoteThread");

	result = 0;
	WriteProcessMemory(hProcess, p_remote_arg, (t_info -> arg).arg, (t_info -> arg).arg_size, &result);
	if (result < (t_info -> arg).arg_size)
		error_msg_with_exit("result < (t_info -> arg).arg_size in executionRemoteThread");

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)p_remote_code, p_remote_arg, 0, NULL);
	if (hThread == NULL)
		error_msg_with_exit("hThread == NULL in executionRemoteThread");

	if (WaitForSingleObject(hThread, INFINITE) == 0xFFFFFFFF)
		error_msg_with_exit("WaitForSingleObject(hThread, INFINITE) == 0xFFFFFFFF in executionRemoteThread");

	if (!GetExitCodeThread(hThread, &(t_info->ret_val)))
		error_msg_with_exit("GetExitCodeThread(hThread, &(t_info->ret_val)) in executionRemoteThread");

	if (!CloseHandle(hThread))
		error_msg_with_exit("CloseHandle(hThread) in executionRemoteThread");

	result = 0;
	ReadProcessMemory(hProcess, p_remote_arg, (t_info -> arg).arg, (t_info -> arg).arg_size, &result);
	if (result < (t_info -> arg).arg_size)
		error_msg_with_exit("result < (t_info -> arg).arg_size in executionRemoteThread");

	if (!VirtualFreeEx(hProcess, p_remote_code, 0, MEM_RELEASE))
		error_msg_with_exit("VirtualFreeEx(hProcess, p_remote_code, 0, MEM_RELEASE) in executionRemoteThread");

	if (!VirtualFreeEx(hProcess, p_remote_arg, 0, MEM_RELEASE))
		error_msg_with_exit("VirtualFreeEx(hProcess, p_remote_arg, 0, MEM_RELEASE) in executionRemoteThread");

	return 0;
}

int main() {

	STARTUPINFO info;
	PROCESS_INFORMATION pi;
	ZeroMemory(&info, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	if (!CreateProcess(TASK_MNGR, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &info, &pi)) 
		error_msg_with_exit("CreateProcess");
	else {
		patch_t p_info;
		ZeroMemory(&p_info, sizeof(patch_t));

		make_patch(pi, &p_info);
		if (ResumeThread(pi.hThread) == -1)
			error_msg_with_exit("ResumeThread");

		Sleep(1000);

		void *proc_kernel32 = findKernel32Address_x64(pi);
		if (proc_kernel32 == NULL)
			error_msg_with_exit("proc_kernel32 == NULL");

		if (SuspendThread(pi.hThread) == -1)
			error_msg_with_exit("SuspendThread(pi.hThread) == -1");

		if (unmake_patch(pi, &p_info));

		HMODULE hKernel32 = GetModuleHandle(KERNEL32);
		if (!hKernel32)
			error_msg_with_exit("hKernel32 == NULL");

		DWORD LoadLibraryA_RVA = (DWORD)((unsigned char *)LoadLibraryA - (unsigned char *)hKernel32);
		LoadLibrary_t proc_LoadLibraryA = (LoadLibrary_t)((unsigned char *)proc_kernel32 + LoadLibraryA_RVA);

		DWORD GetLastError_RVA = (DWORD)((unsigned char *)GetLastError - (unsigned char *)hKernel32);
		GetLastError_t proc_GetLastError = (GetLastError_t)((unsigned char *)proc_kernel32 + GetLastError_RVA);

		shell_code_info_t s_info;
		s_info.GetLastError_info = proc_GetLastError;
		s_info.LoadLibrary_info = proc_LoadLibraryA;
		strncpy(s_info.my_dll_path, MY_DLL_x64, sizeof(MY_DLL_x64));

		thread_info_t t_info;
		t_info.code.code = byte_code_myLoadLibrary;
		t_info.code.code_size = sizeof(byte_code_myLoadLibrary);
		t_info.arg.arg_size = sizeof(s_info);
		t_info.arg.arg = (unsigned char *)&s_info;

		if (executeRemoteThread(pi, &t_info)) 
			error_msg_with_exit("executionRemoteThread(pi, &t_info)");

		if (ResumeThread(pi.hThread) == -1) 
			error_msg_with_exit("ResumeThread(pi.hThread) == -1");

		if (WaitForSingleObject(pi.hThread, INFINITE) == 0xFFFFFFFF) 
			error_msg_with_exit("WaitForSingleObject(pi.hThread, INFINITE) == 0xFFFFFFFF");

		if (!GetExitCodeThread(pi.hThread, &(t_info.ret_val))) 
			error_msg_with_exit("GetExitCodeThread(pi.hThread, &(t_info.ret_val))");

		if (!CloseHandle(pi.hThread))
			error_msg_with_exit("CloseHandle(pi.hThread)");

		printf("Program succesfully finished.\n");
	}
    return 0;
}

