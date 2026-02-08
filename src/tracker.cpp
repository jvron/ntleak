
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

MemTracker tracker; // global tracker variable definition

void MemTracker::init()
{   
    capacity = 10000;
    count = 0;

    record = (AllocRecord*) VirtualAlloc(NULL, capacity * sizeof(AllocRecord), MEM_COMMIT, PAGE_READWRITE);

    if (record == NULL)
    {
        record = nullptr;
        std::cout << "tracker init allocation failed\n";
    }

    symInit = false;
}


void MemTracker::trackAlloc(size_t size, void* ptr)
{
    record[count] = {size, ptr, true};
    record[count].frames = CaptureStackBackTrace(0, MAX_FRAMES, record[count].callStack, NULL);
    count++;   
}

void MemTracker::trackFree(void *ptr)
{
    for (int i = count - 1; i >= 0; i--)
    {   
        
        if(record[i].address == ptr && record[i]. active == true) 
        {
            record[i].active = false;
            return; //prevent making unfreed memory as freed if it has the same address
        }
    }
}

void MemTracker::resolveSymbols(AllocRecord &record)
{   
    
    if (!symInit)
    {
        hProcess = GetCurrentProcess(); //unique identifier to current process
        if (!SymInitialize(hProcess, NULL, TRUE))
        {
            DWORD error = GetLastError();
            std::cout << "Symbol init failed: " << error << "\n";
        }
        else {

            symInit = true;
        }

    }

  
    for (int i = 0; i < record.frames; i++)
    {   
        if (record.callStack[i] == nullptr) continue; 

        DWORD64 address = (DWORD64) record.callStack[i];
        char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];

        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO) buffer;

        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;
        
        
        if (SymFromAddr(hProcess, address, 0, pSymbol))
        {
            //record.resolvedStack[i] = pSymbol->Name; 
            strncpy_s(record.resolvedStack[i], MAX_SYM_NAME, pSymbol->Name, _TRUNCATE);
        }
        else  {
            DWORD error = GetLastError();
            std::cout << "symFromAdrr returned error :" << error << "\n"; 
        }
    }
    
}

void resolve(MemTracker &tracker)
{
    for (int i = 0; i < tracker.count; i++ )
    {
        tracker.resolveSymbols(tracker.record[i]);
    }
}


void MemTracker::report()
{
    std::cout << "================ Memory Leak Report ================\n";
    
    for (int i = 0; i < count; i++)
    {
        

        std::cout << "Allocation #" << i << ": "
                  << record[i].size << " bytes at " << record[i].address << "\n";

        if (!record[i].active)
        {
            std::cout << "\tStatus: FREED\n";
        }
        else
        {
            std::cout << "\tStatus: LEAKED\n";
        }

        if (record[i].frames > 0)
        {
            std::cout << "\tStack Trace (" << record[i].frames << " frames):\n";

            for (USHORT j = 0; j < record[i].frames; j++)
            {
                std::cout << "\t\t[" << j << "] " 
                          << record[i].resolvedStack[j] << "\n";
            }
        }
        std::cout << "---------------------------------------------------\n";
    }

    std::cout << "================ End of Report ====================\n";
}


void MemTracker::shutdown()
{
    BOOL result = VirtualFree(record, 0, MEM_RELEASE);
    
    if (result == 0)
    {
        std::cout << "virtualFree failed\n";
        return;
    }

    record = nullptr;

    SymCleanup(hProcess);
}

