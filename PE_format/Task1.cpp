#include "stdafx.h"
#include <stdlib.h>
#include <windows.h>
#include "atlstr.h"
#include <iostream>
#include "my_dia2.h"
#include <malloc.h>

#define _CRT_SECURE_NO_WARNINGS

HANDLE hFile = INVALID_HANDLE_VALUE;
HANDLE hFileMapping = NULL;
Name_addr_map_t FuncAddrNameMap;

//Functions, dealing with file mapping/unmapping
PVOID openPEFile(char *peName) {
	wchar_t wtext[1000];
	mbstowcs(wtext, peName, strlen(peName) + 1);
	LPWSTR ptr = wtext;
	hFile = CreateFile(ptr, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (INVALID_HANDLE_VALUE == hFile) {
		printf("Failed to open %s with error %d \n", peName, GetLastError());
		return NULL;
	}
	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (NULL == hFileMapping) {
		printf("Failed to create mapping %s with error %d \n", peName, GetLastError());
		CloseHandle(hFile);
		return NULL;
	}
	PVOID pImageBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (NULL == pImageBase) {
		printf("Failed to map %s with error %d \n", peName, GetLastError());
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return NULL;
	}
	return pImageBase;
}

void closePEFile(PVOID pImageBase) {
	if ((pImageBase != NULL) && (hFileMapping != NULL) && (hFile != INVALID_HANDLE_VALUE)) {
		UnmapViewOfFile(pImageBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
	}
}
//==============================================

//Additional functions to cope with x86 and x64 architecture
PIMAGE_DATA_DIRECTORY return_directory(PIMAGE_NT_HEADERS pheader) {
	PVOID p_opt_header = (PVOID)(((LPBYTE)pheader) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	if (pheader->FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32)) {
		return ((PIMAGE_OPTIONAL_HEADER32)p_opt_header)->DataDirectory;
	}
	else {
		return ((PIMAGE_OPTIONAL_HEADER64)p_opt_header)->DataDirectory;
	}
}

void print_x86_import_table(PIMAGE_THUNK_DATA32 pImageThunk, ULONG64 flag, PVOID pImageBase, LPDWORD func_number) {
	while (pImageThunk -> u1.AddressOfData) {
		(*func_number)++;
		if (pImageThunk -> u1.Ordinal & flag)
			printf("#%d Func ordinal: %lld\n", (*func_number), pImageThunk -> u1.Ordinal & 0xffff);
		else {
			printf("\t#%d Func hint %d,\t Name: %s\n", (*func_number),
				((PIMAGE_IMPORT_BY_NAME)(pImageThunk -> u1.AddressOfData + (ULONG_PTR)pImageBase)) -> Hint,
				((PIMAGE_IMPORT_BY_NAME)(pImageThunk -> u1.AddressOfData + (ULONG_PTR)pImageBase)) -> Name);
		}
		printf("\n");
		pImageThunk++;
	}
}

void print_x64_import_table(PIMAGE_THUNK_DATA64 pImageThunk, ULONG64 flag, PVOID pImageBase, LPDWORD func_number) {
	while (pImageThunk -> u1.AddressOfData) {
		(*func_number)++;
		if (pImageThunk -> u1.Ordinal & flag)
			printf("#%d Function ordinal: %lld\n", (*func_number), pImageThunk -> u1.Ordinal & 0xffff);
		else {
			printf("\t#%d Func hint %d,\t Name: %s\n", (*func_number),
				((PIMAGE_IMPORT_BY_NAME)(pImageThunk -> u1.AddressOfData + (ULONG_PTR)pImageBase)) -> Hint,
				((PIMAGE_IMPORT_BY_NAME)(pImageThunk -> u1.AddressOfData + (ULONG_PTR)pImageBase)) -> Name);
		}
		printf("\n");
		pImageThunk++;
	}
}
//========================================================

//Functions which get headers
PIMAGE_NT_HEADERS get_PE_header(PVOID pImageBase) {
	return (PIMAGE_NT_HEADERS)(((ULONG_PTR)pImageBase) + ((PIMAGE_DOS_HEADER)((ULONG_PTR)pImageBase))->e_lfanew);
}

PIMAGE_SECTION_HEADER get_section_header(PIMAGE_NT_HEADERS pheader) {
	return (PIMAGE_SECTION_HEADER)(((LPBYTE)pheader) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pheader->FileHeader.SizeOfOptionalHeader);
}
//===========================

//Print headers
void print_DOS_header(PVOID pImageBase) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
	printf("DOS HEADER = %c%c 0x%x \n", pDosHeader->e_magic & 0xFF, (pDosHeader->e_magic >> 8) & 0xFF, pDosHeader->e_lfanew);
	return;
}

void print_PE_header(PIMAGE_NT_HEADERS pheader) {
	printf("PE HEADER = #%c%c%x%x# 0x%x machine=%s \n",
		pheader->Signature & 0xFF,
		(pheader->Signature >> 8) & 0xFF,
		(pheader->Signature >> 16) & 0xFF,
		(pheader->Signature >> 24) & 0xFF,
		pheader->FileHeader.Machine,
		pheader->FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER) ? "x86" : "x64");
	return;
}
//================

//Print tables
void print_section_table(PIMAGE_SECTION_HEADER pSectionHeader, PIMAGE_NT_HEADERS pPeHeader) {
	for (int i = 0; i < pPeHeader->FileHeader.NumberOfSections; i++) {
		printf("SECTION %8s \n", pSectionHeader->Name);
		printf("\t\tVirtSize:\t %6.8x\tVirtAddr:\t%6.8x\n", pSectionHeader->Misc, pSectionHeader->VirtualAddress);
		printf("\t\traw data offs:\t %6.8x\traw data size:\t%6.8x\n", pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
		printf("\t\trelocation_offs: %6.8x\trelocations:\t%6.8x\n", pSectionHeader->PointerToRelocations, pSectionHeader->NumberOfRelocations);
		printf("\t\tline # offs:\t %6.8x\tline #'s:\t%6.8x\n", pSectionHeader->PointerToLinenumbers, pSectionHeader->NumberOfLinenumbers);
		printf("\t\tCharacteristics: %6.8x\n\n", (pSectionHeader++)->Characteristics);
	}
}

void print_import_table(PIMAGE_NT_HEADERS pheader, PVOID pImageBase) {
	printf("\n\n\t\tIMPORT TABLE\n\n");

	IMAGE_DATA_DIRECTORY dataDir = (return_directory(pheader))[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (dataDir.VirtualAddress == NULL) {
		printf("File doesn't have import table!\n");
		return;
	}
	LPDWORD import_func_number = (LPDWORD)malloc(sizeof(DWORD));
	memset((PVOID)import_func_number, 0, sizeof(DWORD));

	size_t import_size = dataDir.Size;
	size_t import_entries_num = import_size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	printf("Size of ImportTable:\t\t %zu\n", import_size);
	printf("Number of ImportTable entries:\t %zu\n\n", import_entries_num);
	if ((import_entries_num * sizeof(IMAGE_IMPORT_DESCRIPTOR)) != import_size) {
		printf("Size of import table is not equal to number of functions multipled with size of import table entry!\n");
		return;
	}

	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pImageBase + dataDir.VirtualAddress);

	while (pImport -> Characteristics) {
		printf("\n");
		printf("DLL name: %s \n", pImport -> Name + (ULONG_PTR)pImageBase);
		printf("\n");

		WORD machine = pheader -> FileHeader.Machine;
		ULONG64 flag = 0;

		if (machine == IMAGE_FILE_MACHINE_AMD64) {
			PIMAGE_THUNK_DATA64 pImageThunk = (PIMAGE_THUNK_DATA64)(pImport -> OriginalFirstThunk + (ULONG_PTR)pImageBase);
			if (pImport -> OriginalFirstThunk == NULL) {
				pImageThunk = (PIMAGE_THUNK_DATA64)(pImport -> FirstThunk + (ULONG_PTR)pImageBase);
			}
			ULONG64 flag = IMAGE_ORDINAL_FLAG64;
			print_x64_import_table(pImageThunk, flag, pImageBase, import_func_number);
		}
		else {
			PIMAGE_THUNK_DATA32 pImageThunk = (PIMAGE_THUNK_DATA32)(pImport->OriginalFirstThunk + (ULONG_PTR)pImageBase);
			if (pImport->OriginalFirstThunk == NULL) {
				pImageThunk = (PIMAGE_THUNK_DATA32)(pImport->FirstThunk + (ULONG_PTR)pImageBase);
			}
			ULONG64 flag = IMAGE_ORDINAL_FLAG32;
			print_x86_import_table(pImageThunk, flag, pImageBase, import_func_number);
		}
		pImport++;
	}
	free(import_func_number);
	return;
}

void print_export_table(PIMAGE_NT_HEADERS pheader, PVOID pImageBase) {
	printf("\n\n\t\tEXPORT TABLE\n\n");

	IMAGE_DATA_DIRECTORY dataDir = (return_directory(pheader))[IMAGE_DIRECTORY_ENTRY_EXPORT];

	DWORD exportDirOffset = dataDir.VirtualAddress;
	if (exportDirOffset == NULL) {
		printf("File doesn't have export table!\n");
		return;
	}
	
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pImageBase + exportDirOffset);
	printf("Name of file, export table comes from: %s \n", (char*)(pExportDir -> Name + (ULONG_PTR)pImageBase));

	LPDWORD addrTable = (LPDWORD)((ULONG_PTR)pImageBase + pExportDir->AddressOfFunctions);
	LPDWORD nameTable = (LPDWORD)((ULONG_PTR)pImageBase + pExportDir->AddressOfNames);
	LPWORD ordTable = (LPWORD)((ULONG_PTR)pImageBase + pExportDir->AddressOfNameOrdinals);
	WORD base = pExportDir->Base;

	WORD entries = pExportDir->NumberOfFunctions;
	printf("Number of functions: %d\n", entries);

	if (entries > pExportDir->NumberOfNames) {
		entries = pExportDir->NumberOfNames;
		printf("Number of names: %d\n", entries);
	}
	printf("Number of entries: %d\n\n", entries);

	for (int i = 0; i < pExportDir->NumberOfFunctions; ++i) {
		DWORD RVA = addrTable[i];
		if (RVA == 0) {
			continue;
		}
		for (int j = 0; j < pExportDir->NumberOfNames; j++) {
			if (ordTable[j] + base == i) {
				printf("Address: 0x%08x\t Name of Ordinal: %d\t  Name: %s\n", addrTable[i], ordTable[i] + base, (LPCWSTR)((ULONG_PTR)pImageBase + nameTable[ordTable[j]]));
				break;
			}
		}
	}
	return;
}

//Parse PDB
void extract_from_exe_and_pdb(PIMAGE_NT_HEADERS pheader, PVOID pImageBase, char *pdb_name, int pdb_provided) {

	IMAGE_DATA_DIRECTORY debugDir = (return_directory(pheader))[IMAGE_DIRECTORY_ENTRY_DEBUG];
	if (debugDir.VirtualAddress == NULL) {
		printf("Doesn't have debug section!\n");
		return;
	}

	PIMAGE_DEBUG_DIRECTORY p_debug = (PIMAGE_DEBUG_DIRECTORY)((ULONG_PTR)pImageBase + debugDir.VirtualAddress);
	PIMAGE_DEBUG_DIRECTORY p_debug_entry = p_debug;
	
	//These values are expected to be found in .pdb file. Matching is an operation, which allow debbuger
	//to find out if both .exe and .pdb files are 
	DWORD Signature = 0;
	GUID GUID = GUID_NULL;
	DWORD Age = 0;
	BYTE* PdbFileName = NULL;

	size_t debug_size = debugDir.Size;
	size_t debug_entries_num = debug_size / sizeof(IMAGE_DEBUG_DIRECTORY);
	printf("Number of Debug entries: %zu", debug_entries_num);
	if ((debug_entries_num * sizeof(IMAGE_DEBUG_DIRECTORY)) != debug_size) {
		printf("Size of .debug is not equal to number of functions multipled with size of debug entry!\n");
		return;
	}

	//I am looking for IMAGE_DEBUG_TYPE_CODEVIEW entry.
	
	DWORD i;
	for (i = 0; i < debug_entries_num; i++) {
		if (p_debug_entry -> Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
			printf("IMAGE_DEBUG_TYPE_CODEVIEW has been found.\n\n");
			break;
		}
		else if (i == debug_entries_num - 1) {
			p_debug_entry = NULL;
			break;
		}
		p_debug_entry++;
	}

	//If such entry found
	if (p_debug_entry != NULL) {
		ULONG_PTR CvInfo = p_debug_entry -> AddressOfRawData + (ULONG_PTR)pImageBase;

		if ((((PCV_INFO_PDB20)CvInfo)->CvHeader.CvSignature & 0xFF) == 'N') {  //NB10

			Signature = ((PCV_INFO_PDB20)CvInfo)->Signature;
			Age = ((PCV_INFO_PDB20)CvInfo)->Age;
			PdbFileName = ((PCV_INFO_PDB20)CvInfo)->PdbFileName;

			printf("CV_INFO_PDB20: Signature: %u\n", Signature);
			printf("               Age: %u\n", Age);
			printf("               PdbFileName: %s\n", PdbFileName);

		}
		else if ((((PCV_INFO_PDB70)CvInfo)->CvSignature & 0xFF) == 'R') {// RSDS

			GUID = ((PCV_INFO_PDB70)CvInfo)->Signature;
			Age = ((PCV_INFO_PDB70)CvInfo)->Age;
			PdbFileName = ((PCV_INFO_PDB70)CvInfo)->PdbFileName;

			printf("CV_INFO_PDB70: GUID: {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\n", GUID.Data1, GUID.Data2, GUID.Data3,
				GUID.Data4[0], GUID.Data4[1], GUID.Data4[2], GUID.Data4[3], GUID.Data4[4], GUID.Data4[5], GUID.Data4[6], GUID.Data4[7]);

			printf("               Age: %u\n", Age);
			printf("               PdbFileName: %s\n", PdbFileName);
		}
		else
			printf("Invalid CV_INFO_PDBXX\n");
	}

	//Dia SDK
	IDiaDataSource *g_pDiaDataSource = NULL;
	IDiaSession *g_pDiaSession = NULL;
	IDiaSymbol *g_pGlobalSymbol = NULL;
	const wchar_t *g_szFilename = NULL;

	bool is_pdb_matches = 0;
	std::wstring RuntimeFuncName;
	if ((pdb_name == NULL) && (PdbFileName == NULL)) {
		printf("There is no pdb file!\n");
		return;
	}
	else if ((pdb_name == NULL) && (PdbFileName != NULL)) {
		printf("May try 'ExpectedPdbFile': %s...\n\n", PdbFileName);
		pdb_name = (char *)PdbFileName;
		pdb_provided = 1;
	}

	if (pdb_provided == 1) {
		//-----------------------------------------------------------------------------
		// convert 'pdb_name' from 'char*' to 'wchar_t*'
		size_t newsize = strlen(pdb_name) + 1;  
		wchar_t * w_pdb_name = new wchar_t[newsize];

		// Convert char* string to a wchar_t* string.  
		size_t convertedChars = 0;
		mbstowcs_s(&convertedChars, w_pdb_name, newsize, pdb_name, _TRUNCATE);
		//-----------------------------------------------------------------------------

		g_szFilename = w_pdb_name;

		if (LoadAndValidateDataFromPdb(g_szFilename, &g_pDiaDataSource, &g_pDiaSession, &g_pGlobalSymbol, &GUID, Signature, Age)) {
			printf(".pdb matches exe/dll.\n");

			size_t sz = FuncAddrNameMap.size();

			if (DumpAllPublicsToMap(g_pGlobalSymbol, &FuncAddrNameMap)) {
				is_pdb_matches = true;
				printf("number of mapped funcs: %zd\n\n", FuncAddrNameMap.size());
			}
			if (DumpAllGlobalsToMap(g_pGlobalSymbol, &FuncAddrNameMap)) {
				is_pdb_matches = true;
				printf("number of mapped funcs: %zd\n\n", FuncAddrNameMap.size() - sz);
			}
		}
	}
}

//Print .pdata with function information from PDB
void print_pdata(PIMAGE_NT_HEADERS pheader, PVOID pImageBase) {
	printf("\n\n\t\t.pdata .xdata\n\n");

	IMAGE_DATA_DIRECTORY exceptionDir = (return_directory(pheader))[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (exceptionDir.VirtualAddress == NULL) {
		printf("Doesn't have .pdata section!\n");
		return;
	}

	PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY p_pdata = (PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY)((ULONG_PTR)pImageBase + exceptionDir.VirtualAddress);
	PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY p_runtime_entry = p_pdata;

	size_t pdata_size = exceptionDir.Size;
	size_t pdata_entries_num = pdata_size / sizeof(PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY);
	printf("Number of Runtime_Function entries: %zu", pdata_entries_num);
	if ((pdata_entries_num * sizeof(PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY)) != pdata_size) {
		printf("Size of .pdata is not equal to number of functions multipled with size of runtime entry!\n");
		return;
	}

	DWORD i;
	for (i = 0; i < pdata_entries_num; i++) {
		printf("RUNTIME_FUNCTION #%ld: ", i + 1);
		
		//Prints name of the function
		Name_addr_map_t::const_iterator got = FuncAddrNameMap.find((ULONG_PTR)(p_runtime_entry->BeginAddress));
		if (got != FuncAddrNameMap.end())
			std::wcout << got->second << std::endl;
		else
			std::wcout << std::endl;

		printf(" BeginAddress = %p,\n", (ULONG_PTR)(p_runtime_entry -> BeginAddress));
		printf(" EndAddress   = %p,\n", (ULONG_PTR)(p_runtime_entry -> EndAddress));

		if (((p_runtime_entry -> UnwindInfoAddress) & 1) == 0) { //Address is alligned
			printf(" UnwindInfoAddress = %p\n", (ULONG_PTR)(p_runtime_entry -> UnwindInfoAddress));

			/*Version number of the unwind data, currently 1*/
			PUNWIND_INFO UnwindInfoAddress = (PUNWIND_INFO)(p_runtime_entry -> UnwindInfoAddress + (ULONG_PTR)pImageBase);
			printf("\t Version = %d %s\n", UnwindInfoAddress -> Version, (UnwindInfoAddress -> Version == 1) ? "" : "BAD\n");
			if (UnwindInfoAddress -> Version != 1)
				continue;
			
			/*
			Three flags are currently defined:
			1) UNW_FLAG_EHANDLER
			2) UNW_FLAG_UHANDLER 
			3) UNW_FLAG_CHAININFO
			*/

			BYTE flags = UnwindInfoAddress -> Flags;
			printf("\t Flags: %s %s %s\n", (flags & UNW_FLAG_EHANDLER) ? "UNW_FLAG_EHANDLER" : "",
										   (flags & UNW_FLAG_UHANDLER) ? "UNW_FLAG_UHANDLER" : "",
										   (flags & UNW_FLAG_CHAININFO) ? "UNW_FLAG_CHAININFO" : "");

			PVariable pUNWIND_INFO = (PVariable)(&(UnwindInfoAddress->UnwindCode[(UnwindInfoAddress -> CountOfCodes + 1) & ~1]));

			/*
				UNW_FLAG_EHANDLER - The function has an exception handler that should be called
			when looking for functions that need to examine exceptions.
			
				UNW_FLAG_UHANDLER - The function has a termination handler that should be called 
			when unwinding an exception.
			*/

			if ((flags & UNW_FLAG_EHANDLER) || (flags & UNW_FLAG_UHANDLER)) {
				printf("\t Address of %s handler = %p, ", (flags & UNW_FLAG_EHANDLER) ? "exception" : "termination", (ULONG_PTR)(pUNWIND_INFO -> ExceptionHandlerInfo.pExceptionHandler));

				Name_addr_map_t::const_iterator got = FuncAddrNameMap.find((ULONG_PTR)(pUNWIND_INFO->ExceptionHandlerInfo.pExceptionHandler));
				if (got != FuncAddrNameMap.end())
				{
					printf("name of %s handler: ", (flags & UNW_FLAG_EHANDLER) ? "exception" : "termination");
					std::wcout << got->second << std::endl;
				}
				else
					std::wcout << std::endl;
			}
			else if (flags & UNW_FLAG_CHAININFO)
				printf("\t another 'Chained Unwind Info' is here\n");
			
			printf("\t size of prolog = %d\n", UnwindInfoAddress -> SizeOfProlog);
			printf("\t count of codes = %d\n", UnwindInfoAddress -> CountOfCodes);
			printf("\t frame register = %d\n", UnwindInfoAddress -> FrameRegister);
			printf("\t frame offset = %d\n", UnwindInfoAddress -> FrameOffset);

			BYTE codes_count = UnwindInfoAddress -> CountOfCodes;
			DWORD i;
			for (i = 0; i < codes_count; i++) {
				printf("\t\t UNWIND_CODE #%d: offset in prolog = %u\n", i, UnwindInfoAddress -> UnwindCode[i].CodeOffset);

				BYTE Unwind_Op = UnwindInfoAddress -> UnwindCode[i].UnwindOp;
				printf("\t\t                 unwind operation code = %u : ", Unwind_Op);

				if (Unwind_Op == UWOP_PUSH_NONVOL)			printf("UWOP_PUSH_NONVOL\n");
				else if (Unwind_Op == UWOP_ALLOC_LARGE)		printf("UWOP_ALLOC_LARGE\n");
				else if (Unwind_Op == UWOP_ALLOC_SMALL)		printf("UWOP_ALLOC_SMALL\n");
				else if (Unwind_Op == UWOP_SET_FPREG)		printf("UWOP_SET_FPREG\n");
				else if (Unwind_Op == UWOP_SAVE_NONVOL)		printf("UWOP_SAVE_NONVOL\n");
				else if (Unwind_Op == UWOP_SAVE_NONVOL_FAR) printf("UWOP_SAVE_NONVOL_FAR\n");
				else if (Unwind_Op == UWOP_SAVE_XMM128)		printf("UWOP_SAVE_XMM128\n");
				else if (Unwind_Op == UWOP_SAVE_XMM128_FAR) printf("UWOP_SAVE_XMM128_FAR\n");
				else if (Unwind_Op == UWOP_PUSH_MACHFRAME)	printf("UWOP_PUSH_MACHFRAME\n");
				else										printf("'UnwindOp' is unknown");
			
				printf("\t\t                 operation info = %d\n", UnwindInfoAddress -> UnwindCode[i].OpInfo);
			}
		}
		else printf(" UnwindData = %p\n", (ULONG_PTR)(p_runtime_entry->UnwindData));
		
		printf("\n");
		p_runtime_entry++;
	}
}

//=================================================MAIN================================================
int main(int argc, char* argv[]) {
	//Examples of DLLs////////////////////////////////////////////////////////////////////////////////
	char *exe_file = "C:\\Program Files (x86)\\Microsoft Office\\Office16\\EXCEL.exe";
	char *dll_file = "C:\\Program Files (x86)\\Microsoft Office\\Office16\\AUDIOSEARCHLTS.DLL";
	char *x64_dll = "C:\\Users\\artem\\SysProg\\Parallels\\PE_header\\dlls\\ucrtbased.dll";
	char *pdb_name = "C:\\Users\\artem\\SysProg\\Parallels\\PE_header\\dlls\\ucrtbased.pdb";
	int pdb_provided = 1;
	//////////////////////////////////////////////////////////////////////////////////////////////////
	
	PVOID pImageBase = openPEFile(exe_file);
	if (pImageBase == NULL) {
		printf("Problem with pImageBase!\n");
		return 1;
	}

	PIMAGE_NT_HEADERS pheader = get_PE_header(pImageBase);
	PIMAGE_SECTION_HEADER pSectionHeader = get_section_header(pheader);
	
	print_DOS_header(pImageBase);
	print_PE_header(pheader);
	print_section_table(pSectionHeader, pheader);
	print_import_table(pheader, pImageBase);
	print_export_table(pheader, pImageBase);
	extract_from_exe_and_pdb(pheader, pImageBase, pdb_name, pdb_provided);
	//print_pdata(pheader, pImageBase);

	closePEFile(pImageBase);
	return 0;
}
//=====================================================================================================
