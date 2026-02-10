#include <windows.h>
#include <iomanip>
#include <errhandlingapi.h>
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
        }
        else {
            symInit = true;
        }
    }

    for (int i = 0; i < allocMap.hashGroups; i++)
    {   
        AllocRecord &record = allocMap.table[i];

        if (record.status != USED) continue;

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
        }
    } 
}

void MemTracker::report()
{
    size_t totalLeaked = 0;
    size_t leakCount = 0;
    
    // Statistics for categorization
    size_t smallLeaks = 0;      // < 1 KB
    size_t mediumLeaks = 0;     // 1 KB - 1 MB
    size_t largeLeaks = 0;      // > 1 MB
    size_t maxLeakSize = 0;
    void* maxLeakAddress = nullptr;
    
    // First pass: Collect statistics and categorize leaks
    for (int i = 0; i < HashTable::hashGroups; i++)
    {
        AllocRecord& rec = allocMap.table[i];
        
        if (rec.status != USED || !rec.active)
            continue;
            
        totalLeaked += rec.size;
        leakCount++;
        
        // Categorize by size
        if (rec.size < 1024)
            smallLeaks++;
        else if (rec.size < 1048576)
            mediumLeaks++;
        else
            largeLeaks++;
            
        // Track largest leak
        if (rec.size > maxLeakSize)
        {
            maxLeakSize = rec.size;
            maxLeakAddress = rec.address;
        }
    }
    
    // Helper lambda to format bytes
    auto formatBytes = [](size_t bytes) -> std::string {
        const char* units[] = {"B", "KB", "MB", "GB"};
        double size = static_cast<double>(bytes);
        int unitIndex = 0;
        
        while (size >= 1024.0 && unitIndex < 3)
        {
            size /= 1024.0;
            unitIndex++;
        }
        
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << size << " " << units[unitIndex];
        return oss.str();
    };
    
    // Print report header
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "               MEMORY LEAK REPORT\n";
    std::cout << std::string(60, '=') << "\n\n";
    
    // Print summary statistics
    std::cout << "SUMMARY:\n";
    std::cout << std::string(40, '-') << "\n";
    std::cout << "Total Leaks Detected:    " << std::setw(10) << leakCount << " allocations\n";
    std::cout << "Total Memory Leaked:     " << std::setw(10) << formatBytes(totalLeaked) << "\n";
    
    if (leakCount > 0)
    {
        std::cout << "Average Leak Size:       " << std::setw(10) 
                  << formatBytes(totalLeaked / leakCount) << "\n";
        std::cout << "Largest Single Leak:     " << std::setw(10) 
                  << formatBytes(maxLeakSize) << " at 0x" 
                  << std::hex << reinterpret_cast<uintptr_t>(maxLeakAddress) 
                  << std::dec << "\n";
        
        // Print categorization
        std::cout << "\nCATEGORIZATION:\n";
        std::cout << std::string(40, '-') << "\n";
        std::cout << "Small leaks (< 1 KB):    " << std::setw(10) << smallLeaks 
                  << " (" << std::setw(5) << std::fixed << std::setprecision(1)
                  << (smallLeaks * 100.0 / leakCount) << "%)\n";
        std::cout << "Medium leaks (1 KB-1MB): " << std::setw(10) << mediumLeaks 
                  << " (" << std::setw(5) << std::fixed << std::setprecision(1)
                  << (mediumLeaks * 100.0 / leakCount) << "%)\n";
        std::cout << "Large leaks (>= 1 MB):   " << std::setw(10) << largeLeaks 
                  << " (" << std::setw(5) << std::fixed << std::setprecision(1)
                  << (largeLeaks * 100.0 / leakCount) << "%)\n";
    }
    std::cout << "\n";
    
    // Early return if no leaks
    if (leakCount == 0)
    {
        std::cout << "No memory leaks detected. All allocations have been properly freed.\n\n";
        std::cout << std::string(60, '=') << "\n";
        return;
    }
    
    
    std::cout << "DETAILED LEAK INFORMATION:\n";
    std::cout << std::string(60, '-') << "\n\n";
    
    int leakIndex = 1;
    const char* systemPatterns[] = {
        "RtlUserThreadStart",
        "BaseThreadInitThunk",
        "__scrt_",
        "invoke_main",
        "malloc",
        "calloc",
        "realloc",
        "HeapAlloc",
        "detour",
        "operator new",
        "operator delete",
        "std::"
    };
    
    for (int i = 0; i < HashTable::hashGroups; i++)
    {
        AllocRecord& rec = allocMap.table[i];
        
        if (rec.status != USED || !rec.active)
            continue;
            
        // Print leak header with index
        std::cout << "LEAK #" << leakIndex++ << ":\n";
        std::cout << "  Address: 0x" << std::hex << std::setfill('0') << std::setw(sizeof(void*)*2)
                  << reinterpret_cast<uintptr_t>(rec.address) << std::dec << std::setfill(' ') << "\n";
        std::cout << "  Size:     " << std::setw(12) << formatBytes(rec.size) 
                  << " (" << rec.size << " bytes)\n";
        
        // Print call stack with filtering
        std::cout << "  Call Stack (user-relevant frames):\n";
        
        bool hasUserFrames = false;
        int frameNumber = 0;
        
        for (USHORT j = 0; j < rec.frames; j++)
        {
            const char* symbol = rec.resolvedStack[j];
            if (!symbol || symbol[0] == '\0')
                continue;
                
            // Check if this is a system frame
            bool isSystemFrame = false;
            for (const char* pattern : systemPatterns)
            {
                if (strstr(symbol, pattern) != nullptr)
                {
                    isSystemFrame = true;
                    break;
                }
            }
            
            // Print only user frames (or all if none found)
            if (!isSystemFrame)
            {
                std::cout << "    [" << std::setw(2) << frameNumber++ << "] " << symbol << "\n";
                hasUserFrames = true;
            }
        }
        
        // If no user frames were found, print all frames
        if (!hasUserFrames)
        {
            std::cout << "    [No user frames found. Showing full stack:]\n";
            for (USHORT j = 0; j < rec.frames; j++)
            {
                if (rec.resolvedStack[j][0] != '\0')
                {
                    std::cout << "    [" << std::setw(2) << j << "] " 
                              << rec.resolvedStack[j] << "\n";
                }
            }
        }
        
        // Add separator between leaks
        if (leakIndex <= leakCount)
        {
            std::cout << std::string(40, '-') << "\n\n";
        }
    }
    
    // Print recommendations if leaks are found
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "RECOMMENDATIONS:\n";
    std::cout << std::string(60, '-') << "\n";
    if (largeLeaks > 0)
    {
        std::cout << "CRITICAL: " << largeLeaks 
                  << " large memory leak(s) detected (> 1 MB each).\n"
                  << "          These should be investigated immediately as they can\n"
                  << "          quickly lead to out-of-memory conditions.\n\n";
    }
    if (mediumLeaks > 0)
    {
        std::cout << "WARNING:  " << mediumLeaks 
                  << " medium memory leak(s) detected.\n"
                  << "          Investigate these leaks as they can accumulate over time.\n\n";
    }
    if (smallLeaks > 0)
    {
        std::cout << "INFO:     " << smallLeaks 
                  << " small memory leak(s) detected.\n"
                  << "          While individually small, these should still be fixed\n"
                  << "          to maintain code quality and prevent accumulation.\n";
    }
    
    std::cout << std::string(60, '=') << "\n";
}


void MemTracker::shutdown()
{

    SymCleanup(hProcess);
}

