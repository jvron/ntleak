#include <windows.h>
#include <errhandlingapi.h>
#include <cstddef>
#include <libloaderapi.h>
#include <memoryapi.h>
#include <minwindef.h>
#include <winnt.h>
#include <iostream>

#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

#include "tracker.h"
#include "alloc_map.h"

MemTracker tracker; // global tracker variable definition

void MemTracker::init()
{   
    capacity = MAX_CAPACITY;
    allocCount = 0;

    allocMap = HashTable();

    symInit = false;
}


void MemTracker::trackAlloc(size_t size, void* ptr)
{
    
    AllocRecord rec;
    rec.address = ptr;
    rec.size = size;
    rec.active = true;

    rec.frames = CaptureStackBackTrace(2, MAX_FRAMES, rec.callStack, NULL);

    rec.status = USED;

    allocMap.insertItem(ptr, rec);

    allocCount++;
      
}

void MemTracker::trackFree(void *ptr)
{   

    AllocRecord *rec = allocMap.searchTable(ptr);

    if( rec->address == ptr && rec->active == true)
    {
        rec->active = false;
    }
}

void MemTracker::resolveSymbols()
{   
    
    if (!symInit)
    {
        hProcess = GetCurrentProcess(); //unique identifier to current process
        if (!SymInitialize(hProcess, NULL, TRUE))
        {
            DWORD error = GetLastError();
            std::cerr << "Symbol init failed: " << error << "\n";
        }
        else {

            symInit = true;
        }

    }

    for (int i = 0; i < allocMap.hashGroups; i++)
    {   
        AllocRecord &record = allocMap.table[i];

        for (int n = 0; n < MAX_FRAMES; n++)
        {   

            if (record.callStack[n] == nullptr) continue; 
        
            DWORD64 address = (DWORD64) record.callStack[n];
            char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
        
            PSYMBOL_INFO pSymbol = (PSYMBOL_INFO) buffer;
        
            pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
            pSymbol->MaxNameLen = MAX_SYM_NAME;
            
            
            if (SymFromAddr(hProcess, address, 0, pSymbol))
            {
                //record.resolvedStack[i] = pSymbol->Name; 
                strncpy_s(record.resolvedStack[n], MAX_SYM_NAME, pSymbol->Name, _TRUNCATE);
            }
            else  {
                DWORD error = GetLastError();
                std::cout << "symFromAdrr returned error :" << error << "\n"; 
            }
        }
    }
        
    
}
void MemTracker::report()
{
    size_t totalLeaked = 0;
    size_t leakCount = 0;

    // Count leaks and total leaked bytes
    for (int i = 0; i < HashTable::hashGroups; i++)
    {
        AllocRecord& rec = allocMap.table[i];
        if (rec.status == USED && rec.active)
        {
            totalLeaked += rec.size;
            leakCount++;
        }
    }

    std::cout << "\n=== MEMORY LEAK REPORT ===\n";
    std::cout << "Leaks: " << leakCount << " allocations, " << totalLeaked << " bytes\n\n";

    if (leakCount == 0)
    {
        std::cout << "No leaks detected.\n";
        return;
    }

    // Iterate hash table and show details
    for (int i = 0; i < HashTable::hashGroups; i++)
    {
        AllocRecord& rec = allocMap.table[i];
        if (rec.status != USED || !rec.active) continue;

        std::cout << "LEAK: " << rec.size << " bytes at " << rec.address << "\n";

        bool foundUserCode = false;

        for (USHORT j = 0; j < rec.frames; j++)
        {
            const char* symbol = rec.resolvedStack[j];
            if (!symbol || symbol[0] == '\0') continue;

            // Skip common CRT/system frames
            if (strstr(symbol, "RtlUserThreadStart") ||
                strstr(symbol, "BaseThreadInitThunk") ||
                strstr(symbol, "__scrt_") ||
                strstr(symbol, "invoke_main") ||
                strstr(symbol, "malloc") ||
                strstr(symbol, "HeapAlloc") ||
                strstr(symbol, "detour"))
            {
                continue;
            }

            foundUserCode = true;
            std::cout << "  " << symbol << "\n";
        }

        // If all frames were filtered, print full stack trace
        if (!foundUserCode)
        {
            for (USHORT j = 0; j < rec.frames; j++)
            {
                if (rec.resolvedStack[j][0] != '\0')
                    std::cout << "  " << rec.resolvedStack[j] << "\n";
            }
        }

        std::cout << "\n";
    }
}



void MemTracker::shutdown()
{

    SymCleanup(hProcess);
}

