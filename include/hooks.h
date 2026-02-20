#pragma once

#include <MinHook.h>
#include <cstddef>
#include <memoryapi.h>
#include <minwindef.h>
#include <stdlib.h>
#include <winnt.h>

extern DWORD g_tlsHeapAlloc;
extern DWORD g_tlsMalloc;
extern DWORD g_tlsRealloc;
extern DWORD g_tlsOperatorNew;

MH_STATUS initMinHook();
MH_STATUS uninitMinHook();

void detourEntry(void);

void* detourMalloc(size_t size);
void detourFree(void* ptr);

void* detourOperatorNew(size_t size);
void detourOperatorDelete(void* ptr);

void* detourOperatorNewArray(size_t size);
void detourOperatorDeleteArray(void* ptr);


LPVOID detourHeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
BOOL detourHeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);

LPVOID detourHeapRealloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);

LPVOID detourVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL detourVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

MH_STATUS hookEntry();

MH_STATUS hookHeapAlloc();
MH_STATUS hookHeapFree();

MH_STATUS hookRealloc();
MH_STATUS hookHeapReAlloc();

MH_STATUS hookVirtualAlloc();
MH_STATUS hookVirtualFree();

MH_STATUS hookMalloc();
MH_STATUS hookFree();

MH_STATUS hookOperatorNew();
MH_STATUS hookOperatorDelete();

MH_STATUS hookOperatorNewArray();
MH_STATUS hookOperatorDeleteArray();

MH_STATUS createHooks();
MH_STATUS enableHooks();
MH_STATUS disableHooks();
MH_STATUS removeHooks();
