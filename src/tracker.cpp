#include <corecrt.h>
#include <cstring>
#include <windows.h>
#include <iomanip>
#include <cstddef>
#include <libloaderapi.h>
#include <memoryapi.h>
#include <minwindef.h>
#include <winnt.h>
#include <iostream>
#include <sstream>


#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

#include "tracker.h"
#include "alloc_map.h"

MemTracker tracker; // global tracker variable definition

void MemTracker::init()
{   
    capacity = MAX_CAPACITY;
    allocCount = 0;

    symInit = false;
}


void MemTracker::trackAlloc(size_t size, void* ptr)
{
    if (trackingEnabled)
    {
        AllocRecord rec {0};
        rec.address = ptr;
        rec.size = size;
        rec.active = true;
    
        rec.frames = CaptureStackBackTrace(2, MAX_FRAMES, rec.callStack, NULL);
    
        rec.status = USED;
    
        allocMap.insertItem(ptr, rec);
    
        allocCount++;
    }
      
}

void MemTracker::trackFree(void *ptr)
{   

    if (trackingEnabled)
    {
        AllocRecord *rec = allocMap.searchTable(ptr);
    
        if (rec == nullptr) //if rec is nullptr (arises in case if double free, etc) we return
        {
            return;
        }
    
        if(rec->address == ptr && rec->active == true)
        {
            rec->active = false;
        }
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
            return; //return if symInit fails
        }
        else {
            SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);
            //SymSetSearchPath(hProcess, ".;C:\\Dev\\ntleak");
            symInit = true;
        }
    }

    for (int i = 0; i < allocMap.hashGroups; i++)
    {   
        AllocRecord &record = allocMap.table[i];

        if (record.status != USED ) continue;

        for (int n = 0; n < record.frames; n++)
        {   
            if (record.callStack[n] == nullptr) continue; 
        
            DWORD64 address = (DWORD64) record.callStack[n];
            char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
        
            PSYMBOL_INFO pSymbol = (PSYMBOL_INFO) buffer;
        
            pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
            pSymbol->MaxNameLen = MAX_SYM_NAME;
            
            
            if (SymFromAddr(hProcess, address, 0, pSymbol))
            {
                strncpy_s(record.resolvedStack[n], MAX_SYM_NAME, pSymbol->Name, _TRUNCATE);
            }
            else  {
                DWORD error = GetLastError();
                std::cout << "symFromAdrr returned error :" << error << "\n"; 
            }


            //get file and line info
            IMAGEHLP_LINE64 Line;
            DWORD displacement = 0;

            Line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

            if (SymGetLineFromAddr64(hProcess, address, &displacement, &Line))
            {

                record.lineNum[n] = Line.LineNumber;
                strncpy_s(record.fileName[n], MAX_PATH, Line.FileName, _TRUNCATE);
            }
            else {
                
                //if unavailable
                record.lineNum[n] = 0; 
                record.fileName[n][0] = '\0';

            }

        }
    } 
}

void MemTracker::report()
{
    size_t totalLeaked = 0;
    size_t leakCount = 0;
    size_t smallLeaks = 0, mediumLeaks = 0, largeLeaks = 0;
    size_t maxLeakSize = 0;
    void* maxLeakAddress = nullptr;

    // First pass: gather stats
    for (int i = 0; i < HashTable::hashGroups; i++)
    {
        AllocRecord& rec = allocMap.table[i];
        if (rec.status != USED || !rec.active)
            continue;

        totalLeaked += rec.size;
        leakCount++;

        if (rec.size < 1024) smallLeaks++;
        else if (rec.size < 1048576) mediumLeaks++;
        else largeLeaks++;

        if (rec.size > maxLeakSize)
        {
            maxLeakSize = rec.size;
            maxLeakAddress = rec.address;
        }
    }

    auto formatBytes = [](size_t bytes) -> std::string {
        const char* units[] = {"B", "KB", "MB", "GB"};
        double sz = static_cast<double>(bytes);
        int idx = 0;
        while (sz >= 1024.0 && idx < 3) { sz /= 1024.0; idx++; }
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << sz << " " << units[idx];
        return oss.str();
    };

    // Print summary
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "               MEMORY LEAK REPORT\n";
    std::cout << std::string(60, '=') << "\n\n";
    std::cout << "SUMMARY:\n" << std::string(40, '-') << "\n";
    std::cout << "Total Leaks Detected: " << leakCount << "\n";
    std::cout << "Total Memory Leaked:  " << formatBytes(totalLeaked) << "\n";
    if (leakCount > 0)
    {
        std::cout << "Average Leak Size:    " << formatBytes(totalLeaked / leakCount) << "\n";
        std::cout << "Largest Leak:         " << formatBytes(maxLeakSize) 
                  << " at 0x" << std::hex << reinterpret_cast<uintptr_t>(maxLeakAddress) << std::dec << "\n";
    }
    std::cout << "\n";

    if (leakCount == 0)
    {
        std::cout << "No memory leaks detected.\n";
        std::cout << std::string(60, '=') << "\n";
        return;
    }

    // Print detailed info
    std::cout << "DETAILED LEAK INFORMATION:\n" << std::string(60, '-') << "\n\n";
    int leakIndex = 1;
    for (int i = 0; i < HashTable::hashGroups; i++)
    {
        AllocRecord& rec = allocMap.table[i];
        if (rec.status != USED || !rec.active) continue;

        std::cout << "LEAK #" << leakIndex++ << ":\n";
        std::cout << "  Address: 0x" << std::hex << reinterpret_cast<uintptr_t>(rec.address) << std::dec << "\n";
        std::cout << "  Size:    " << formatBytes(rec.size) << " (" << rec.size << " bytes)\n";

        // Find first valid source location across all frames
        bool foundSource = false;
        for (USHORT j = 0; j < rec.frames && !foundSource; j++)
        {
            if (rec.fileName[j][0] != '\0' && rec.lineNum[j] != 0)
            {
                std::cout << "  Source:  " << rec.fileName[j] << ":" << rec.lineNum[j] << "\n";
                foundSource = true;
            }
        }

        std::cout << "  Call Stack:\n";
        bool hasUserFrames = false;
        for (USHORT j = 0; j < rec.frames; j++)
        {
            const char* sym = rec.resolvedStack[j];
            if (!sym || sym[0] == '\0') continue;

            // Filter system frames
            const char* systemPatterns[] = {
                "RtlUserThreadStart","BaseThreadInitThunk","__scrt_",
                "invoke_main","malloc","calloc","realloc","HeapAlloc",
                "detour","operator new","operator delete","std::"
            };
            bool isSystem = false;
            for (const char* p : systemPatterns)
                if (strstr(sym, p)) { isSystem = true; break; }

            if (!isSystem)
            {
                std::cout << "    [" << j << "] " << sym;
                
                // Show file/line if available for this frame
                if (rec.fileName[j][0] != '\0' && rec.lineNum[j] != 0)
                {
                    std::cout << " (" << rec.fileName[j] << ":" << rec.lineNum[j] << ")";
                }
                std::cout << "\n";
                
                hasUserFrames = true;
            }
        }

        if (!hasUserFrames)
        {
            std::cout << "    [No user frames, showing full stack]\n";
            for (USHORT j = 0; j < rec.frames; j++)
            {
                if (rec.resolvedStack[j][0] != '\0')
                {
                    std::cout << "    [" << j << "] " << rec.resolvedStack[j];
                    
                    // Show file/line if available
                    if (rec.fileName[j][0] != '\0' && rec.lineNum[j] != 0)
                    {
                        std::cout << " (" << rec.fileName[j] << ":" << rec.lineNum[j] << ")";
                    }
                    std::cout << "\n";
                }
            }
        }

        std::cout << std::string(40, '-') << "\n\n";
    }

    // Recommendations
    std::cout << "RECOMMENDATIONS:\n" << std::string(60, '-') << "\n";
    if (largeLeaks)  std::cout << "CRITICAL: " << largeLeaks << " large leak(s) detected.\n";
    if (mediumLeaks) std::cout << "WARNING:  " << mediumLeaks << " medium leak(s) detected.\n";
    if (smallLeaks)  std::cout << "INFO:     " << smallLeaks << " small leak(s) detected.\n";
    std::cout << std::string(60, '=') << "\n";
}



void MemTracker::shutdown()
{

    SymCleanup(hProcess);
}

