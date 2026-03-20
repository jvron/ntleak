#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <iostream>

#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

#include "hooks.h"
#include "tracker.h"
#include "alloc_map.h"

//function pointers that points to the original funtion. MinHook will store the target functions in these function pointers
void (*pEntryOriginal)(void) = NULL;

void* (*pMallocOriginal)(size_t size) = NULL;
void (*pFreeOriginal)(void* ptr) = NULL;
void* (*pReallocOriginal)(void* memptr, size_t size) = NULL; 

LPVOID (*pHeapAllocOriginal)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) = NULL;
BOOL (*pHeapFreeOriginal) (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) = NULL;

LPVOID (*pHeapReAllocOriginal) (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes) = NULL;

LPVOID (*pVirtualAllocOriginal) (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = NULL;
BOOL (*pVirtualFreeOriginal) (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) = NULL; 

PVOID (*pRtlAllocateHeapOriginal)(PVOID HeapHandle, ULONG Flags, SIZE_T Size) = NULL;
BOOLEAN (*pRtlFreeHeapOriginal)(PVOID HeapHandle, ULONG Flags, PVOID HeapBase) = NULL;


VOID (*pExitProcessOriginal) (UINT uExitCode) = NULL;

void* mallocAddr = NULL;
void* freeAddr = NULL;
void* reallocAddr = NULL;


void* heapAllocAddr = NULL;
void* heapReAllocAddr = NULL;
void* heapFreeAddr = NULL;

void* virtualAllocAddr = NULL;
void* virtualFreeAddr = NULL;

void* rtlAllocateHeapAddr = NULL;
void* rtlFreeHeapAddr = NULL;

//tls flags
DWORD g_tlsHeapAlloc = TLS_OUT_OF_INDEXES;
DWORD g_tlsMalloc = TLS_OUT_OF_INDEXES;
DWORD g_tlsRealloc = TLS_OUT_OF_INDEXES;


MH_STATUS initMinHook()
{
    MH_STATUS status;
    status = MH_Initialize();
    if(status != MH_OK) return status;
    return status;
}
MH_STATUS uninitMinHook()
{
    MH_STATUS status;
    status = MH_Uninitialize();
    if(status != MH_OK) return status;
    return status;
}

void detourEntry()
{   
    tracker.trackingEnabled = false;

    pEntryOriginal();
}

void* detourMalloc(size_t size)
{   
    if (TlsGetValue(g_tlsMalloc))
    {
        return pMallocOriginal(size);
    }

    TlsSetValue(g_tlsMalloc, (LPVOID) 1);
    
    void *memptr = pMallocOriginal(size);
       
    if (memptr != NULL )
    {
        tracker.trackAlloc(size, memptr, MALLOC);
    };
    //printf("malloc returned: %p for size: %zu\n", memptr, size);
        
    TlsSetValue(g_tlsMalloc, (LPVOID) 0);
    return memptr;
}

void detourFree(void *ptr)
{   
    pFreeOriginal(ptr);
    tracker.trackFree(ptr);
    //printf("free called at: %p\n", ptr);
}

void* detourRealloc(void *memptr, size_t size)
{   
    
    TlsSetValue(g_tlsRealloc, (LPVOID) 1);

    void* newptr = pReallocOriginal(memptr, size);

    if(newptr != NULL)
    {   
        if (memptr == NULL) //same as malloc
        {
            tracker.trackAlloc(size, newptr, REALLOC);
        }

        else if (newptr != memptr) // new pointer returned by realloc, old ptr freed
        {
            tracker.trackFree(memptr);
            tracker.trackAlloc(size, newptr, REALLOC);
        }
        
        else if (newptr == memptr)
        {
            tracker.trackAlloc(size, memptr, REALLOC); // replace the old allocation with new size
        }
    }
    else { // newptr == NULL

        if (size == 0)
        {
            // same as free
            tracker.trackFree(memptr);
        }
    }

    //printf("realloc called at: %p\n", memptr);
    //printf("realloc returned: %p\n", newptr);
    TlsSetValue(g_tlsRealloc, (LPVOID) 0);
    return newptr;
}


LPVOID detourHeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{   
    //TlsSetValue( g_tlsMalloc, (LPVOID) 0);
    //TlsSetValue(g_tlsRealloc, (LPVOID) 0);

    if (TlsGetValue(g_tlsHeapAlloc))
    {   //reentrancy
        return  pHeapAllocOriginal(hHeap, dwFlags, dwBytes);
    }

    TlsSetValue(g_tlsHeapAlloc, (LPVOID)1);

    void* memptr = pHeapAllocOriginal(hHeap, dwFlags, dwBytes);
    //printf("HeapAlloc returned: %p\n", memptr);
    
    if (memptr != NULL ) // do not track heapAlloc triggered by malloc and realloc
    {   
        if (tracker.trackingEnabled && !TlsGetValue(g_tlsMalloc) && !TlsGetValue(g_tlsRealloc))
        {
            tracker.trackAlloc(dwBytes, memptr, HEAP_ALLOC);
            //printf("HeapAlloc returned: %p\n", memptr);
        }
    } 
    
    TlsSetValue(g_tlsHeapAlloc, (LPVOID)0);
    return memptr;
}

BOOL detourHeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    BOOL result = pHeapFreeOriginal(hHeap, dwFlags, lpMem);

    if (result != 0)
    {
        tracker.trackFree(lpMem);
        //printf("heapFree tracking: %p\n", lpMem);
    }

    return result;
}

LPVOID detourHeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
{
    //TlsSetValue( g_tlsMalloc, (LPVOID) 0);
    //TlsSetValue(g_tlsRealloc, (LPVOID) 0);

    void* newptr = pHeapReAllocOriginal(hHeap, dwFlags, lpMem, dwBytes);

    if(newptr != NULL)
    {   
        if (!TlsGetValue(g_tlsMalloc) && !TlsGetValue(g_tlsRealloc))
        {
            if (lpMem == NULL) //same as HeapAlloc
            {   
                tracker.trackAlloc(dwBytes, newptr, HEAP_REALLOC);
            }
            else if (newptr != lpMem) // new pointer returned by HeapReAlloc, old ptr freed
            {
                tracker.trackFree(lpMem);
                tracker.trackAlloc(dwBytes, newptr, HEAP_REALLOC);
            }
            else if (newptr == lpMem)
            {   
                tracker.trackFree(lpMem);
                tracker.trackAlloc(dwBytes, lpMem, HEAP_REALLOC); // replace the old allocation with new size
            }
        }
    }
    else  
    {
        if (dwBytes == 0 && !TlsGetValue(g_tlsMalloc) && !TlsGetValue(g_tlsRealloc))
        {
            tracker.trackFree(lpMem);
        }
    }

    //printf("HeapReAlloc called at: %p\n", memptr);
    //printf("HeapReAlloc returned: %p\n", newptr);
    return newptr;
}

PVOID detourVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    void* memptr = pVirtualAllocOriginal(lpAddress, dwSize, flAllocationType, flProtect);

    if (memptr != NULL)
    {
        tracker.trackAlloc(dwSize, memptr, VIRTUAL_ALLOC);
    }
    return memptr;
}

BOOL detourVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    BOOL result = pVirtualFreeOriginal(lpAddress, dwSize, dwFreeType);

    if (result != 0)
    {
        tracker.trackFree(lpAddress);
    }

    return result;
}

PVOID detourRtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size)
{
    void* memptr = pRtlAllocateHeapOriginal(HeapHandle, Flags, Size);

    if (memptr != NULL)
    {   
        if (!TlsGetValue(g_tlsHeapAlloc) && !TlsGetValue(g_tlsMalloc) && !TlsGetValue(g_tlsRealloc))
        {
            //tracker.trackAlloc(Size, memptr);
        }
    }

    return memptr;
}

BOOLEAN detourRtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID HeapBase)
{
    BOOLEAN result = pRtlFreeHeapOriginal(HeapHandle, Flags, HeapBase);

    if (result != 0)
    {
        tracker.trackFree(HeapBase);
    }

    return result;
}

VOID detourExitProcess(UINT uExitCode)
{   
    tracker.trackingEnabled = false;
    tracker.trackFreeEnabled = false;

    MH_STATUS status;
    status = disableHooks();
    status = removeHooks();
    status = uninitMinHook();

    tracker.resolveSymbols();
    tracker.report();
    tracker.shutdown();

    //safe to call ExitProcess directly as hooks are removed
    ExitProcess(uExitCode);
}


MH_STATUS hookEntry()
{
    MH_STATUS status;

    //entry
    // get the handle of the current exe module
    HMODULE hExe = GetModuleHandle(NULL);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hExe;

    PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64) ((BYTE*)hExe + dosHeader->e_lfanew);

    void* entryPoint = (BYTE*) hExe + ntHeader->OptionalHeader.AddressOfEntryPoint;

    status = MH_CreateHook(entryPoint,(void*)&detourEntry, reinterpret_cast<LPVOID*>(&pEntryOriginal));
    if (status != MH_OK) return status;

    status = MH_EnableHook(entryPoint);
    if (status != MH_OK) return status;

    return status;
}

MH_STATUS hookMalloc()
{
    MH_STATUS status;

    status = MH_EnableHook((void*)mallocAddr);

    if (status != MH_OK)
    {
        return status;
    }
    return status;
}

MH_STATUS hookFree()
{
    MH_STATUS status;

    status = MH_EnableHook((void*)freeAddr);
    if (status != MH_OK)
    {
        return status;
    }

    return status;
}

MH_STATUS hookRealloc()
{
    MH_STATUS status;

    status = MH_EnableHook((void*)reallocAddr);
    if (status != MH_OK)
    {
        return status;
    }

    return status;
}

MH_STATUS hookHeapAlloc()
{
    MH_STATUS status;

    status = MH_EnableHook((void*)heapAllocAddr);
    if (status != MH_OK)
    {
        return status;
    }

    return status;
}

MH_STATUS hookHeapReAlloc()
{
    MH_STATUS status;

    status = MH_EnableHook((void*)heapReAllocAddr);
    if (status != MH_OK)
    {
        return status;
    }

    return status;
}

MH_STATUS hookVirtualAlloc()
{
    MH_STATUS status;

    status = MH_EnableHook((void*)&VirtualAlloc);
    if (status != MH_OK)
    {
        return status;
    }

    return status;
}

MH_STATUS hookHeapFree()
{
    MH_STATUS status;

    status = MH_EnableHook((void*)heapFreeAddr);
  
    if (status != MH_OK)
    {
        return status;
    }
    
    return status;
}

MH_STATUS hookVirtualFree()
{
    MH_STATUS status;
    status = MH_EnableHook((void*)&VirtualFree);
  
    if (status != MH_OK)
    {
        return status;
    }
    
    return status;
}

MH_STATUS hookRtlAllocateHeap()
{
    MH_STATUS status;
    status = MH_EnableHook((void*)rtlAllocateHeapAddr);
    if (status != MH_OK)
    {
        return status;
    }
    return status;
}

MH_STATUS hookRtlFreeHeap()
{
    MH_STATUS status;
    status = MH_EnableHook((void*)rtlFreeHeapAddr);
    if (status != MH_OK)
    {
        return status;
    }
    return status;
}

MH_STATUS hookExitProcess()
{
    MH_STATUS status;

    status = MH_EnableHook((void*)&ExitProcess);
  
    if (status != MH_OK)
    {
        return status;
    }
    
    return status;
}

MH_STATUS createHooks()
{   
    MH_STATUS status = MH_UNKNOWN;

    DWORD modulesBuffSize = 512;
    DWORD cbNeeded = 0; //bytes needed

    HMODULE *hModules = (HMODULE*) malloc(modulesBuffSize * sizeof(HMODULE));
    if (hModules == NULL)
    {   
        std::cerr << "Failed to allocate memory for modules.\n";
        return status;
    }

    if(EnumProcessModules(GetCurrentProcess(),hModules, modulesBuffSize * sizeof(HMODULE), &cbNeeded))
    {   
        if (cbNeeded > modulesBuffSize * sizeof(HMODULE))
        {
            modulesBuffSize = cbNeeded;

            hModules = (HMODULE*) realloc(hModules, modulesBuffSize * sizeof(HMODULE));
            if (hModules != NULL )
            {
                EnumProcessModules(GetCurrentProcess(),hModules, modulesBuffSize * sizeof(HMODULE), &cbNeeded);
            }
        }
    }
    else {
        std::cerr << "Module enumeration failed\n";  
    }

    int moduleCount = cbNeeded / sizeof(HMODULE);
    char moduleFilePath[MAX_PATH];

    HMODULE hCRTModule = NULL;
    const char* crtModuleName = NULL;
    const char* vcrtModuleName = NULL;
    HMODULE hKernel32 = NULL;
    //HMODULE hVCRuntime = NULL;
    //HMODULE hNtdll = NULL;

    for (int i = 0; i < moduleCount; i++)
    {
        GetModuleFileNameA(hModules[i], moduleFilePath, sizeof(moduleFilePath));

        char* moduleName = PathFindFileNameA(moduleFilePath);

        if (strcmp(moduleName, "ucrtbase.dll") == 0)
        {
            hCRTModule = hModules[i];
            tracker.linktype = DYNAMIC;
            crtModuleName = "ucrtbase.dll";
            break;
        }
        else if (strcmp(moduleName, "ucrtbased.dll") == 0) 
        {   
            hCRTModule = hModules[i];
            tracker.linktype = DYNAMIC_DEBUG;
            crtModuleName = "ucrtbased.dll";
            break;
        }
        else if (strcmp(moduleName, "msvcrt.dll") == 0) 
        {
            hCRTModule = hModules[i];
            tracker.linktype = DYNAMIC;
            crtModuleName = "msvcrt.dll";
            break;
        }
    
    }

    if (tracker.linktype == UNKOWN)
    {   //if no dynamic crt modules are found assume that its statically linked  
        tracker.linktype = STATIC;
    }

    if(hCRTModule == NULL)
    {
        mallocAddr = (void*)&malloc;
        reallocAddr = (void*)&realloc;
        freeAddr = (void*)&free;
       
    }
    else {
        mallocAddr = (void*) GetProcAddress(hCRTModule, "malloc");
        freeAddr = (void*)  GetProcAddress(hCRTModule, "free");
        reallocAddr = (void*) GetProcAddress(hCRTModule, "realloc");
    }

    //kernel32.dll is guaranteed
    hKernel32 = GetModuleHandleA("kernel32.dll");
    if(hKernel32 == NULL)
    {
        heapAllocAddr = (void*)&HeapAlloc;
        heapFreeAddr = (void*)&HeapFree;
        heapReAllocAddr = (void*)&HeapReAlloc;

        virtualAllocAddr = (void*)&VirtualAlloc;
        virtualFreeAddr = (void*)&VirtualFree;
    }
    else {
        heapAllocAddr = (void*) GetProcAddress(hKernel32, "HeapAlloc");
        heapFreeAddr = (void*) GetProcAddress(hKernel32, "HeapFree");
        heapReAllocAddr = (void*) GetProcAddress(hKernel32, "HeapReAlloc");
        
        virtualAllocAddr = (void*) GetProcAddress(hKernel32, "VirtualAlloc");
        virtualFreeAddr = (void*) GetProcAddress(hKernel32, "VirtualFree");
    }

/*
    hNtdll = GetModuleHandleA("ntdll.dll");

    if (hNtdll == NULL)
    {
        //rtlAllocateHeapAddr = (void*)&RtlAllocateHeap;
        //rtlFreeHeapAddr = (void*)&RtlFreeHeap;
    }
    else {
        rtlAllocateHeapAddr = (void*) GetProcAddress(hNtdll, "RtlAllocateHeap");
        rtlFreeHeapAddr = (void*) GetProcAddress(hNtdll, "RtlFreeHeap");
    }
*/

    //malloc
    status = MH_CreateHook((void*)mallocAddr, (void*) &detourMalloc, reinterpret_cast<LPVOID*>(&pMallocOriginal));
    if(status != MH_OK)
    {
        return status;
    }
    //free
    status = MH_CreateHook((void*)freeAddr, (void*) &detourFree, reinterpret_cast<LPVOID*>(&pFreeOriginal));

    if(status != MH_OK)
    {
        return status;
    }
    //realloc
    status = MH_CreateHook((void*)reallocAddr, (void*) &detourRealloc, reinterpret_cast<LPVOID*>(&pReallocOriginal));

    if(status != MH_OK)
    {
        return status;
    }

    //heapalloc
    
    status = MH_CreateHook((void*)heapAllocAddr, (void*) &detourHeapAlloc, reinterpret_cast<LPVOID*>(&pHeapAllocOriginal));
    if(status != MH_OK)
    {
        return status;
    }
   
    //heaprealloc
    status = MH_CreateHook((void*)heapReAllocAddr, (void*) &detourHeapReAlloc, reinterpret_cast<LPVOID*>(&pHeapReAllocOriginal));

    if(status != MH_OK)
    {
        return status;
    }

    //heapfree
    status = MH_CreateHook((void*)heapFreeAddr, (void*) &detourHeapFree, reinterpret_cast<LPVOID*>(&pHeapFreeOriginal));
    if(status != MH_OK)
    {
        return status;
    }

    //virtual alloc
    status = MH_CreateHook((void*)virtualAllocAddr, (void*) &detourVirtualAlloc, reinterpret_cast<LPVOID*>(&pVirtualAllocOriginal));

    if(status != MH_OK)
    {
        return status;
    }

    //virtualfree
    status = MH_CreateHook((void*)virtualFreeAddr, (void*) &detourVirtualFree, reinterpret_cast<LPVOID*>(&pVirtualFreeOriginal));

    if(status != MH_OK)
    {
        return status;
    }

    //rtlallocateheap
    /*
    status = MH_CreateHook((void*)rtlAllocateHeapAddr, (void*)&detourRtlAllocateHeap, reinterpret_cast<LPVOID*>(&pRtlAllocateHeapOriginal));
    if(status != MH_OK)
    {   
        printf("%s\n",MH_StatusToString(status));
        //return status;
    }

    status = MH_CreateHook((void*)rtlFreeHeapAddr, (void*)&detourRtlFreeHeap, reinterpret_cast<LPVOID*>(&pRtlFreeHeapOriginal));
    if(status != MH_OK)
    {
        return status;
    }
    */
    status = MH_CreateHook((void*)&ExitProcess, (void*) &detourExitProcess, reinterpret_cast<LPVOID*>(&pExitProcessOriginal));
    if(status != MH_OK)
    {
        return status;
    }

    return status;
}

MH_STATUS enableHooks()
{
    MH_STATUS status = MH_UNKNOWN;

    status = hookMalloc();
    if(status != MH_OK) return status;
    
    status = hookRealloc();
    if(status != MH_OK) return status;

    status = hookFree();
    if(status != MH_OK) return status;

    status = hookVirtualAlloc();
    if(status != MH_OK) return status;

    status = hookVirtualFree();
    if(status != MH_OK) return status;

    status = hookHeapAlloc();
    if(status != MH_OK) return status;

    status = hookHeapFree();
    if(status != MH_OK) return status;

    status = hookHeapReAlloc();
    if(status != MH_OK) return status;

    status = hookExitProcess();
    if(status != MH_OK) return status;

    return status;
}

MH_STATUS disableHooks()
{
    MH_STATUS status = MH_UNKNOWN;

    status = MH_DisableHook((void*)mallocAddr);
    if (status != MH_OK) return status;

    status = MH_DisableHook((void*)freeAddr);
    if (status != MH_OK) return status;

    status = MH_DisableHook((void*)heapAllocAddr);
    if (status != MH_OK) return status;

    status = MH_DisableHook((void*)heapFreeAddr);
    if (status != MH_OK) return status;

    status = MH_DisableHook((void*)reallocAddr);
    if(status != MH_OK) return status;

    status = MH_DisableHook((void*)heapReAllocAddr);
    if(status != MH_OK) return status;
/*
    status = MH_DisableHook((void*)rtlAllocateHeapAddr);
    if(status != MH_OK) return status;
    
    status = MH_DisableHook((void*)rtlFreeHeapAddr);
    if(status != MH_OK) return status;
*/
    status = MH_DisableHook((void*)virtualAllocAddr);
    if(status != MH_OK) return status;

    status = MH_DisableHook((void*)virtualFreeAddr);
    if(status != MH_OK) return status;

    status = MH_DisableHook((void*)&ExitProcess);
    if(status != MH_OK) return status;

    return status;
}

MH_STATUS removeHooks()
{   
    MH_STATUS status = MH_UNKNOWN;

    status = MH_RemoveHook((void*)mallocAddr);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)freeAddr);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)heapAllocAddr);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)heapFreeAddr);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)virtualAllocAddr);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)virtualFreeAddr);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)reallocAddr);
    if(status != MH_OK) return status;
/*
    status = MH_RemoveHook((void*)rtlAllocateHeapAddr);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)rtlFreeHeapAddr);
    if(status != MH_OK) return status;
*/
    status = MH_RemoveHook((void*)&ExitProcess);
    if(status != MH_OK) return status;

    return status;
}
