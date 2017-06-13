#pragma once

extern DWORD g_dwMachineType;
typedef std::unordered_map<ULONG_PTR, std::wstring> Name_addr_map_t;

bool __cdecl LoadAndValidateDataFromPdb(
	const wchar_t    *szFilename,
	IDiaDataSource  **ppSource,
	IDiaSession     **ppSession,
	IDiaSymbol      **ppGlobal,
	GUID*           ExpectedGUID,
	DWORD           ExpectedSignature,
	DWORD           ExpectedAge);

void PrintPublicSymbol(IDiaSymbol *pSymbol);
void AddSymbolToMap(IDiaSymbol *pSymbol, Name_addr_map_t* pFuncAddrNameMap);
bool DumpAllPublicsToMap(IDiaSymbol *pGlobal, Name_addr_map_t* pFuncAddrNameMap);
bool DumpAllGlobalsToMap(IDiaSymbol *pGlobal, Name_addr_map_t* pFuncAddrNameMap);
void Clean(IDiaSymbol** pg_pGlobalSymbol, IDiaSession** pg_pDiaSession);

const wchar_t * const rgTags[] =
{
	L"(SymTagNull)",                     // SymTagNull
	L"Executable (Global)",              // SymTagExe
	L"Compiland",                        // SymTagCompiland
	L"CompilandDetails",                 // SymTagCompilandDetails
	L"CompilandEnv",                     // SymTagCompilandEnv
	L"Function",                         // SymTagFunction
	L"Block",                            // SymTagBlock
	L"Data",                             // SymTagData
	L"Annotation",                       // SymTagAnnotation
	L"Label",                            // SymTagLabel
	L"PublicSymbol",                     // SymTagPublicSymbol
	L"UserDefinedType",                  // SymTagUDT
	L"Enum",                             // SymTagEnum
	L"FunctionType",                     // SymTagFunctionType
	L"PointerType",                      // SymTagPointerType
	L"ArrayType",                        // SymTagArrayType
	L"BaseType",                         // SymTagBaseType
	L"Typedef",                          // SymTagTypedef
	L"BaseClass",                        // SymTagBaseClass
	L"Friend",                           // SymTagFriend
	L"FunctionArgType",                  // SymTagFunctionArgType
	L"FuncDebugStart",                   // SymTagFuncDebugStart
	L"FuncDebugEnd",                     // SymTagFuncDebugEnd
	L"UsingNamespace",                   // SymTagUsingNamespace
	L"VTableShape",                      // SymTagVTableShape
	L"VTable",                           // SymTagVTable
	L"Custom",                           // SymTagCustom
	L"Thunk",                            // SymTagThunk
	L"CustomType",                       // SymTagCustomType
	L"ManagedType",                      // SymTagManagedType
	L"Dimension",                        // SymTagDimension
	L"CallSite",                         // SymTagCallSite
	L"InlineSite",                       // SymTagInlineSite
	L"BaseInterface",                    // SymTagBaseInterface
	L"VectorType",                       // SymTagVectorType
	L"MatrixType",                       // SymTagMatrixType
	L"HLSLType",                         // SymTagHLSLType
	L"Caller",                           // SymTagCaller,
	L"Callee",                           // SymTagCallee,
	L"Export",                           // SymTagExport,
	L"HeapAllocationSite",               // SymTagHeapAllocationSite
	L"CoffGroup",                        // SymTagCoffGroup
};

DWORD g_dwMachineType = CV_CFL_80386;

bool __cdecl LoadAndValidateDataFromPdb(
	const wchar_t    *szFilename,
	IDiaDataSource  **ppSource,
	IDiaSession     **ppSession,
	IDiaSymbol      **ppGlobal,
	GUID*           ExpectedGUID,
	DWORD           ExpectedSignature,
	DWORD           ExpectedAge)
{
	wchar_t wszExt[MAX_PATH];
	wchar_t *wszSearchPath = L"SRV**\\\\symbols\\symbols";
	DWORD dwMachType = 0;

	HRESULT hr = CoInitialize(NULL);

	hr = CoCreateInstance(__uuidof(DiaSource),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(IDiaDataSource),
		(void **)ppSource);

	if (FAILED(hr)) {
		wprintf(L"CoCreateInstance failed - HRESULT = %08X\n", hr);
		return false;
	}
	_wsplitpath_s(szFilename, NULL, 0, NULL, 0, NULL, 0, wszExt, MAX_PATH);

	if (!_wcsicmp(wszExt, L".pdb")) {
		hr = (*ppSource)->loadAndValidateDataFromPdb(szFilename, ExpectedGUID, ExpectedSignature, ExpectedAge);

		if (FAILED(hr)) {
			switch (hr) {
			case E_PDB_NOT_FOUND: printf("E_PDB_NOT_FOUND\n"); break;
			case E_PDB_FORMAT:    printf("E_PDB_FORMAT\n"); break;
			case E_PDB_INVALID_SIG: printf("E_PDB_INVALID_SIG, problem with 'Signature'\n"); break;
			case E_PDB_INVALID_AGE: printf("E_PDB_INVALID_AGE, problem with 'Age'\n"); break;
			case E_INVALIDARG: printf("loadAndValidateDataFromPdb failed - E_INVALIDARG\n"); break;
			case E_UNEXPECTED: printf("loadAndValidateDataFromPdb failed - E_UNEXPECTED\n"); break;
			default: wprintf(L"loadAndValidateDataFromPdb failed - HRESULT = %08X\n", hr);
			}
			return false;
		}
	}
	else {
		CCallback callback;
		callback.AddRef();

		hr = (*ppSource)->loadDataForExe(szFilename, wszSearchPath, &callback);

		if (FAILED(hr)) {
			wprintf(L"loadDataForExe failed - HRESULT = %08X\n", hr);

			return false;
		}
	}

	hr = (*ppSource)->openSession(ppSession);

	if (FAILED(hr)) {
		wprintf(L"openSession failed - HRESULT = %08X\n", hr);
		return false;
	}

	hr = (*ppSession)->get_globalScope(ppGlobal);

	if (hr != S_OK) {
		wprintf(L"get_globalScope failed\n");

		return false;
	}

	if ((*ppGlobal)->get_machineType(&dwMachType) == S_OK) {
		switch (dwMachType) {
		case IMAGE_FILE_MACHINE_I386: g_dwMachineType = CV_CFL_80386; break;
		case IMAGE_FILE_MACHINE_IA64: g_dwMachineType = CV_CFL_IA64; break;
		case IMAGE_FILE_MACHINE_AMD64: g_dwMachineType = CV_CFL_AMD64; break;
		}
	}
	return true;
}

void PrintPublicSymbol(IDiaSymbol *pSymbol) {
	DWORD dwSymTag;
	DWORD dwRVA;
	DWORD dwSeg;
	DWORD dwOff;
	BSTR bstrName;

	if (pSymbol->get_symTag(&dwSymTag) != S_OK) {
		return;
	}

	if (pSymbol->get_relativeVirtualAddress(&dwRVA) != S_OK) {
		dwRVA = 0xFFFFFFFF;
	}

	pSymbol->get_addressSection(&dwSeg);
	pSymbol->get_addressOffset(&dwOff);

	wprintf(L"%X ", dwRVA);

	if (dwSymTag == SymTagThunk) {
		if (pSymbol->get_name(&bstrName) == S_OK) {
			wprintf(L"%s\n", bstrName);

			SysFreeString(bstrName);
		}

		else {
			if (pSymbol->get_targetRelativeVirtualAddress(&dwRVA) != S_OK) {
				dwRVA = 0xFFFFFFFF;
			}

			pSymbol->get_targetSection(&dwSeg);
			pSymbol->get_targetOffset(&dwOff);
		}
	}

	else {
		BSTR bstrUndname;

		if (pSymbol->get_name(&bstrName) == S_OK) {
			if (pSymbol->get_undecoratedName(&bstrUndname) == S_OK) {
				wprintf(L"%s\n", bstrUndname);
				SysFreeString(bstrUndname);
			}
			else {
				wprintf(L"%s\n", bstrName);
			}
			SysFreeString(bstrName);
		}
	}
}

void AddSymbolToMap(IDiaSymbol *pSymbol, Name_addr_map_t* pFuncAddrNameMap) {
	DWORD dwSymTag;
	DWORD dwRVA;
	DWORD dwSeg;
	DWORD dwOff;
	BSTR bstrName;

	ULONG_PTR key;
	std::wstring value;


	if (pSymbol->get_symTag(&dwSymTag) != S_OK) {
		return;
	}

	if (pSymbol->get_relativeVirtualAddress(&dwRVA) != S_OK) {
		dwRVA = 0xFFFFFFFF;
	}

	pSymbol->get_addressSection(&dwSeg);
	pSymbol->get_addressOffset(&dwOff);
	key = dwRVA;

	if (dwSymTag == SymTagThunk) {
		if (pSymbol->get_name(&bstrName) == S_OK) {
			value = bstrName;
			(*pFuncAddrNameMap).insert(Name_addr_map_t::value_type(key, value));
			SysFreeString(bstrName);
		}
		else {
			if (pSymbol->get_targetRelativeVirtualAddress(&dwRVA) != S_OK) {
				dwRVA = 0xFFFFFFFF;
			}
			pSymbol->get_targetSection(&dwSeg);
			pSymbol->get_targetOffset(&dwOff);

			std::wstring test(L"target ->");
			(*pFuncAddrNameMap).insert(Name_addr_map_t::value_type(key, test));
		}
	}
	else {
		BSTR bstrUndname;
		if (pSymbol->get_name(&bstrName) == S_OK) {
			if (pSymbol->get_undecoratedName(&bstrUndname) == S_OK) {
				value = bstrUndname;
				(*pFuncAddrNameMap).insert(Name_addr_map_t::value_type(key, value));
				SysFreeString(bstrUndname);
			}
			else {
				value = bstrName;
				(*pFuncAddrNameMap).insert(Name_addr_map_t::value_type(key, value));
			}
			SysFreeString(bstrName);
		}
	}
}

bool DumpAllPublicsToMap(IDiaSymbol *pGlobal, Name_addr_map_t* pFuncAddrNameMap) {
	IDiaEnumSymbols *pEnumSymbols;

	if (FAILED(pGlobal->findChildren(SymTagPublicSymbol, NULL, nsNone, &pEnumSymbols))) {
		return false;
	}

	IDiaSymbol *pSymbol;
	ULONG celt = 0;

	while (SUCCEEDED(pEnumSymbols->Next(1, &pSymbol, &celt)) && (celt == 1)) {
		AddSymbolToMap(pSymbol, pFuncAddrNameMap);
		pSymbol->Release();
	}
	pEnumSymbols->Release();
	return true;
}

bool DumpAllGlobalsToMap(IDiaSymbol *pGlobal, Name_addr_map_t* pFuncAddrNameMap) {
	IDiaEnumSymbols *pEnumSymbols;
	IDiaSymbol *pSymbol;
	enum SymTagEnum dwSymTags[] = { SymTagFunction };

	ULONG celt = 0;

	for (size_t i = 0; i < _countof(dwSymTags); i++, pEnumSymbols = NULL) {
		if (SUCCEEDED(pGlobal->findChildren(dwSymTags[i], NULL, nsNone, &pEnumSymbols))) {
			while (SUCCEEDED(pEnumSymbols->Next(1, &pSymbol, &celt)) && (celt == 1)) {
				AddSymbolToMap(pSymbol, pFuncAddrNameMap);
				pSymbol->Release();
			}

			pEnumSymbols->Release();
		}
		else {
			return false;
		}
	}
	return true;
}

void Clean(IDiaSymbol** pg_pGlobalSymbol, IDiaSession** pg_pDiaSession) {
	if ((pg_pGlobalSymbol == NULL) || (pg_pDiaSession == NULL)) {
		SetLastError(ERROR_BAD_ARGUMENTS);
		return;
	}

	if (*pg_pGlobalSymbol) {
		(*pg_pGlobalSymbol)->Release();
		*pg_pGlobalSymbol = NULL;
	}

	if (*pg_pDiaSession) {
		(*pg_pDiaSession)->Release();
		*pg_pDiaSession = NULL;
	}
	CoUninitialize();
}