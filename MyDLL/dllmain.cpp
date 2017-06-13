// dllmain.cpp: определяет точку входа для приложения DLL.
#include "stdafx.h"
#include "MyDLL.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved)
{
        switch (ul_reason_for_call)
        {
        case DLL_PROCESS_ATTACH:	
				MessageBox(NULL, TEXT("DLL_PROCESS_ATTACH"), TEXT("MyDLL"), MB_OK | MB_SYSTEMMODAL);
                break;
        case DLL_THREAD_ATTACH:
				MessageBox(NULL, TEXT("DLL_THREAD_ATTACH"), TEXT("MyDLL"), MB_OK | MB_SYSTEMMODAL);
                break;
        case DLL_THREAD_DETACH:
				MessageBox(NULL, TEXT("DLL_THREAD_DETACH"), TEXT("MyDLL"), MB_OK | MB_SYSTEMMODAL);
                break;
        case DLL_PROCESS_DETACH:
				MessageBox(NULL, TEXT("DLL_PROCESS_DETACH"), TEXT("MyDLL"), MB_OK | MB_SYSTEMMODAL);
                break;
        }
        return TRUE;
}

