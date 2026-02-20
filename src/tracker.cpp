#include <windows.h>
#include <psapi.h>
#include <processthreadsapi.h>
#include <MinHook.h>
#include <corecrt.h>
#include <cstring>
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
#include "hooks.h"

MemTracker tracker; // global tracker variable definition

void MemTracker::init()
{    
    allocMap.init();
    capacity = MAX_CAPACITY;
    allocCount = 0;
    //symInit = false;

    g_tlsHeapAlloc = TlsAlloc();
    g_tlsMalloc = TlsAlloc();
    g_tlsRealloc = TlsAlloc();
    g_tlsOperatorNew = TlsAlloc();

    hExe = GetModuleHandle(NULL);
    hProcess = GetCurrentProcess(); //unique identifier to current process

    MODULEINFO mi = {};
    
    if (!GetModuleInformation(hProcess, hExe, &mi, sizeof(mi)))
    {
        DWORD err = GetLastError();
        std::cerr << "GetModuleInformation failed: " << err << "\n";
        return;
    }

    base = (uintptr_t) mi.lpBaseOfDll;
    end = base + mi.SizeOfImage;

    SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);

    if (!SymInitialize(hProcess, NULL, TRUE))
    {
        DWORD error = GetLastError();
        std::cerr << "Symbol init failed: " << error << "\n";
        return; //return if symInit fails
    }
    else {
        //SymSetSearchPath(hProcess, ".;C:\\Dev\\ntleak");
        //symInit = true;
    }
    
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

        if(rec->address == ptr && rec->active == true && rec->status == USED)
        {   
            //printf("free tracked at: %p\n", ptr);
            rec->active = false;
        }
    }
}

void MemTracker::resolveStackTrace(AllocRecord &record)
{

    for (int i = 0; i < record.frames; i++)
    {
        if (record.callStack[i] == nullptr)
        {
            continue;
        }

        DWORD64 displacement = 0;
        DWORD64 address = (DWORD64) record.callStack[i];
        char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
        
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO) buffer;
        
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;
            
        DWORD64 base = SymGetModuleBase64(hProcess, address);

        if (base == 0)
        {
            std::cout << "No module for address: " << std::hex << address << "\n";
        }
                        
        if (SymFromAddr(hProcess, address, &displacement, pSymbol))
        {
            strncpy_s(record.resolvedStack[i], MAX_SYM_NAME, pSymbol->Name, _TRUNCATE);
        }
        else {
            DWORD error = GetLastError();
            printf("[DEBUG] symFromAddr failed for %p, error=%lu\n", record.callStack[i], error);
        }

            //get file and line info
            IMAGEHLP_LINE64 Line;
            DWORD lineDisplacement = 0;
            Line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

            if (SymGetLineFromAddr64(hProcess, address, &lineDisplacement, &Line))
            {

                record.lineNum[i] = Line.LineNumber;
                strncpy_s(record.fileName[i], MAX_PATH, Line.FileName, _TRUNCATE); //copy file name 
            }
            else {
                //if unavailable
                record.lineNum[i] = 0; 
                record.fileName[i][0] = '\0';
            }
    }

}

void MemTracker::resolveSymbols()
{   
    for (int i = 0; i < allocMap.hashGroups; i++)
    {   
        AllocRecord &record = allocMap.table[i];

        if (record.status != USED ) continue;

        for (int n = 0; n < record.frames; n++)
        {   
            if (record.callStack[n] == nullptr) continue; 
            
            DWORD64 displacement = 0;
            DWORD64 address = (DWORD64) record.callStack[n];
            char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
        
            PSYMBOL_INFO pSymbol = (PSYMBOL_INFO) buffer;
        
            pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
            pSymbol->MaxNameLen = MAX_SYM_NAME;
            
            DWORD64 base = SymGetModuleBase64(hProcess, address);

            if (base == 0)
            {
                //std::cout << "No module for address: " << std::hex << address << "\n";
            }
                        
            if (SymFromAddr(hProcess, address, &displacement, pSymbol))
            {
                strncpy_s(record.resolvedStack[n], MAX_SYM_NAME, pSymbol->Name, _TRUNCATE);

            }
            else  {
                DWORD error = GetLastError();
                std::cout << "symFromAdrr returned error: " << error << "\n"; 
            }

            //get file and line info
            IMAGEHLP_LINE64 Line;
            DWORD lineDisplacement = 0;
            Line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

            if (SymGetLineFromAddr64(hProcess, address, &lineDisplacement, &Line))
            {

                record.lineNum[n] = Line.LineNumber;
                strncpy_s(record.fileName[n], MAX_PATH, Line.FileName, _TRUNCATE); //copy file name 
            }
            else {

                //if unavailable
                record.lineNum[n] = 0; 
                record.fileName[n][0] = '\0';
            }

            //get module name

            //get module handle
            HMODULE hMod;
            if (! GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)address, &hMod))
            {
                DWORD error = GetLastError();
                std::cout << "GetModuleHandle returned error: " << error << "\n"; 
            }

            char moduleNameBuff[MAX_PATH];

            if(GetModuleFileName(hMod, moduleNameBuff, sizeof(moduleNameBuff)))
            {
                strncpy_s(record.moduleName[n], MAX_PATH, moduleNameBuff, _TRUNCATE);
            }
            else {
                record.moduleName[n][0] = '\0'; 
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

    //gather stats
    for (int i = 0; i < HashTable::hashGroups; i++)
    {
        AllocRecord &rec = allocMap.table[i];

        if (rec.status != USED || rec.active == false)
        {
            continue;
        }

        if (!isUserLeak(rec))
        {   
            continue;
        }

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

        if (!isUserLeak(rec)) continue;

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
                "invoke_main","mainCRTStartup","calloc","realloc","HeapAlloc", "_malloc_base",
                "detour","operator","operator delete","std::"
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

bool MemTracker::isUserLeak(AllocRecord &rec)
{      
    static const char* crtNoise[] = {
        "mainCRTStartup",
        "wmainCRTStartup", 
        "WinMainCRTStartup",
        "__scrt_common_main",
        "__scrt_common_main_seh",
        "_initterm_e",
        "initterm_e",
        "initterm",
        "set_app_type",
        "pre_c_initialization",
        "pre_cpp_initialization",
        "configure_narrow_argv",
        nullptr
    };
    
    for(int i = 0; i < rec.frames; i++)
    {   
        uintptr_t addr = (uintptr_t) rec.callStack[i];

        char * file = rec.fileName[i];

        if (addr >= base && addr < end)
        {   
            for (int j = 0; crtNoise[j] != nullptr; j++)
            {
                if (strcmp(rec.resolvedStack[i], crtNoise[j]) == 0)
                {
                    return false;
                }
            }

            if (file)
            {
                if ( strstr(file, "\\vctools\\crt\\") || strstr(file, "\\vcstartup\\"))
                {
                    return false;
                }
            }
        }

        else {
            // continue if the stackframe is from outside the exe
            continue;
        }

        // return true only if there is no crtnoise and the allocation is not from vctools/vcstartup
        return true; 
    }

    return false;
}

void MemTracker::shutdown()
{
    SymCleanup(hProcess);
    TlsFree(g_tlsHeapAlloc);
    TlsFree(g_tlsMalloc);
    TlsFree(g_tlsRealloc);
    TlsFree(g_tlsOperatorNew);
}

