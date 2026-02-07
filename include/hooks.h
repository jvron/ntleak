#pragma once

#include <MinHook.h>
#include <stdlib.h>


void* detourMalloc(size_t size);
void detourFree(void* ptr);

MH_STATUS hookMalloc();
MH_STATUS hookFree();

MH_STATUS disableHooks();
