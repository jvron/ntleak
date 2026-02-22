#pragma once

#include <windows.h>
#include <MinHook.h>
#include <cstddef>
#include <memoryapi.h>
#include <minwindef.h>
#include <stdlib.h>
#include <winnt.h>
#include <winternl.h>

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

