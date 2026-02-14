#pragma once

#include <MinHook.h>
#include <memoryapi.h>
#include <minwindef.h>
#include <stdlib.h>


void* detourMalloc(size_t size);
void detourFree(void* ptr);

LPVOID detourHeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
BOOL detourHeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);

LPVOID detourVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL detourVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

MH_STATUS hookHeapAlloc();
MH_STATUS hookHeapFree();

MH_STATUS hookRealloc();

MH_STATUS hookVirtualAlloc();
MH_STATUS hookVirtualFree();

MH_STATUS hookMalloc();
MH_STATUS hookFree();


MH_STATUS removeHooks();
