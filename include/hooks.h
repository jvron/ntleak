#pragma once

#include <MinHook.h>
#include <minwindef.h>

extern DWORD g_tlsHeapAlloc;
extern DWORD g_tlsMalloc;
extern DWORD g_tlsRealloc;
extern DWORD g_tlsOperatorNew;

MH_STATUS initMinHook();
MH_STATUS uninitMinHook();

MH_STATUS hookEntry();

MH_STATUS hookHeapAlloc();
MH_STATUS hookHeapFree();

MH_STATUS hookRealloc();
MH_STATUS hookHeapReAlloc();

MH_STATUS hookVirtualAlloc();
MH_STATUS hookVirtualFree();

MH_STATUS hookMalloc();
MH_STATUS hookFree();

MH_STATUS createHooks();
MH_STATUS enableHooks();
MH_STATUS disableHooks();
MH_STATUS removeHooks();

