#pragma once

#include <MinHook.h>
#include <minwindef.h>
#include <stdlib.h>


void* detourMalloc(size_t size);
void detourFree(void* ptr);
LPVOID detourHeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
BOOL detourHeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);

MH_STATUS hookHeapAlloc();
MH_STATUS hookHeapFree();
MH_STATUS hookMalloc();
MH_STATUS hookFree();


MH_STATUS disableHooks();
