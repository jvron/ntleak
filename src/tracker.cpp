#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

#include "tracker.h"
#include "alloc_map.h"
#include "hooks.h"

MemTracker tracker; // global tracker variable definition

void MemTracker::init()
{    
    allocMap.init();
    capacity = MAX_CAPACITY;
    allocCount = 0;
    linktype = UNKOWN;

    g_tlsHeapAlloc = TlsAlloc();
    g_tlsMalloc = TlsAlloc();
    g_tlsRealloc = TlsAlloc();

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
}

void MemTracker::trackAlloc(size_t size, void* ptr, AllocSource s)
{
    if (trackingEnabled)
    {
        AllocRecord rec {0};
        rec.address = ptr;
        rec.size = size;
        rec.active = true;
        rec.frames = CaptureStackBackTrace(2, MAX_FRAMES, rec.callStack, NULL);
        rec.status = USED;
        rec.source = s;
        allocMap.insertItem(ptr, rec);
    
        allocCount++;
    }
}

void MemTracker::trackFree(void *ptr)
{   
    if (trackFreeEnabled)
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
                strncpy_s(record.resolvedStack[n], MAX_SYM_NAME, "\0" , _TRUNCATE);
                //std::cout << "symFromAdrr returned error: " << error << "\n"; 
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
                //std::cout << "Tracker: GetModuleHandle returned error: " << error << "\n"; 
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

    // Header
    std::cout << "\n";
    std::cout << "==========================================================\n";
    std::cout << "           M E M O R Y   L E A K   R E P O R T\n";
    std::cout << "==========================================================\n\n";

    // Summary
    std::cout << "+- SUMMARY -----------------------------------------------+\n";
    std::cout << "|  Leaks Found   : " << std::left << std::setw(40) << leakCount                << "|\n";
    std::cout << "|  Total Leaked  : " << std::left << std::setw(40) << formatBytes(totalLeaked)  << "|\n";
    if (leakCount > 0)
    {
        std::cout << "|  Average Size  : " << std::left << std::setw(40) << formatBytes(totalLeaked / leakCount) << "|\n";

        std::ostringstream largestOss;
        largestOss << formatBytes(maxLeakSize) << "  @ 0x" << std::hex << reinterpret_cast<uintptr_t>(maxLeakAddress) << std::dec;
        std::cout << "|  Largest Leak  : " << std::left << std::setw(40) << largestOss.str() << "|\n";
        std::cout << "|                                                          |\n";
        std::cout << "|  Breakdown     :  ";
        if (largeLeaks)  std::cout << largeLeaks  << " large  ";
        if (mediumLeaks) std::cout << mediumLeaks << " medium  ";
        if (smallLeaks)  std::cout << smallLeaks  << " small  "  << "                             |";
        std::cout << "\n";
    }
    std::cout << "+---------------------------------------------------------+\n\n";

    if (leakCount == 0)
    {
        std::cout << "  >> No memory leaks detected.\n\n";
        return;
    }

    // Per-leak detail
    std::cout << "+- LEAK DETAILS ------------------------------------------+\n\n";

    int leakIndex = 1;
    for (int i = 0; i < HashTable::hashGroups; i++)
    {
        AllocRecord& rec = allocMap.table[i];

        if (rec.status != USED || !rec.active) continue;
        if (!isUserLeak(rec)) continue;

        std::cout << "  +- Leak #" << leakIndex++ << " " << std::string(50, '-') << "\n";

        std::cout << "  |  Address  :  0x" << std::hex << reinterpret_cast<uintptr_t>(rec.address) << std::dec << "\n";
        std::cout << "  |  Size     :  " << formatBytes(rec.size) << "  (" << rec.size << " bytes)\n";

        for (USHORT j = 0; j < rec.frames; j++)
        {
            if (rec.fileName[j][0] == '\0' || rec.lineNum[j] == 0)
            {
                continue;
            }

            if (strstr(rec.fileName[j], "\\include\\thread") || strstr(rec.fileName[j], "\\vctools\\crt\\") ||
                strstr(rec.fileName[j], "\\vcstartup\\") || strstr(rec.fileName[j], "Program Files") ||
                strstr(rec.fileName[j], "minkernel\\crts\\")) 
            {

                continue;
            }

            std::cout << "  |  Module   :  " << rec.moduleName[j]   << "\n";
            std::cout << "  |  File     :  " << rec.fileName[j]   << "\n";
            std::cout << "  |  Line     :  " << rec.lineNum[j]    << "\n";
            break;
        }

        std::cout << "  |\n";
        std::cout << "  |  Call Stack:\n";

        bool hasUserFrames = false;
        for (USHORT j = 0; j < rec.frames; j++)
        {
            const char* sym = rec.resolvedStack[j];

            if (!sym || sym[0] == '\0')
            {
                continue;
            }   

            const char* systemPatterns[] = {
                "malloc_base","malloc_dbg","RtlUserThreadStart","BaseThreadInitThunk","__scrt_",
                "invoke_main","mainCRTStartup","calloc","realloc","HeapAlloc", "mbsdup_dbg", "heap_alloc_dbg", "heap_alloc_dbg_internal", "malloc", "thread_start", "_strdup_dbg", "_wcsdup_dbg","VirtualAlloc",
                "detour","operator new","operator delete","std::", "register_onexit_function", "beginthreadex", "wcsrchr"
            };
            bool isSystem = false;
            for (const char* p : systemPatterns)
                if (strstr(sym, p)) 
                { 
                    isSystem = true; 
                    break; 
                }

            if (!isSystem)
            {
                std::cout << "  |    [" << std::setw(1) << j << "]  " << sym;

                bool hasLocation = rec.fileName[j][0] != '\0' || rec.lineNum[j] != 0;
                if (hasLocation)
                {
                    std::cout << "  (";
                    if (rec.fileName[j][0] != '\0')
                    {
                        // Just the filename, not the full path
                        const char* slash = strrchr(rec.fileName[j], '\\');
                        std::cout << (slash ? slash + 1 : rec.fileName[j]);
                    }
                    if (rec.lineNum[j] != 0)
                        std::cout << ":" << rec.lineNum[j];
                    std::cout << ")";
                }

                std::cout << "\n";
                hasUserFrames = true;
            }
        }

        if (!hasUserFrames)
        {
            std::cout << "  |    (no user frames -- showing full stack)\n";
            for (USHORT j = 0; j < rec.frames; j++)
            {
                if (rec.resolvedStack[j][0] != '\0')
                {
                    std::cout << "  |    [" << std::setw(2) << j << "]  " << rec.resolvedStack[j] << "\n";
                    if (rec.fileName[j][0] != '\0' && rec.lineNum[j] != 0)
                    {
                        std::cout << "  |          file    >>  " << rec.fileName[j] << "\n";
                        std::cout << "  |          line    >>  " << rec.lineNum[j]  << "\n";
                    }
                }
            }
        }

        std::cout << "  +" << std::string(60, '-') << "\n\n";
    }
}

bool MemTracker::isUserLeak(AllocRecord &rec)
{      
    //filtering is a bit messy :/

    static const char* crtNoise[] = {
        "mainCRTStartup",
        "recalloc_dbg",
        "wmainCRTStartup", 
        "WinMainCRTStartup",
        "__scrt_common_main",
        "__scrt_common_main_seh",
        "_initterm_e",
        "initterm_e",
        "initterm",
        "_initterm",
        "fwrite",
        "printf",
        "_vfprintf_l",
        "unlock_locales",
        "towlower_l",
        "VerifierSetRuntimeFlags",
        "set_se_translator",
        "__acrt_initialize_multibyte",
        "beginthreadex",
        "_beginthreadex",
    
        "register_onexit_function",
        "create_environment<char>",
        "__acrt_allocate_buffer_for_argv",
        "__acrt_stdio_begin_temporary_buffering_nolock",
        "set_app_type",
        "pre_c_initialization",
        "pre_cpp_initialization",
        "configure_narrow_argv",
        "__acrt_get_begin_thread_init_policy",
        "_FC_Query_System",
        "AppPolicyGetWindowingModel",
        "AppPolicyGetThreadInitializationType",

        nullptr
    };

    static const char* systemNoise[] = {
        // ntdll
        "RtlUserThreadStart",
        "RtlInitializeExceptionChain",
        "RtlClearBits",
        "TpReleaseWork",
        "TpWaitForWork",
        "TppWorkpExecuteCallback",
        "TppWorkerThread",
        "LdrInitializeThunk",
        "LdrLoadDll",
        "LdrpLoadDll",
        "LdrpInitialize",
        "NtdllDefWindowProc_A",
        "RtlActivateActivationContextUnsafeFast",

        // kernel32
        "BaseThreadInitThunk",
        "BaseProcessStart",
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "FreeLibrary",
        "CreateThread",

        nullptr
    };

    static const char* externalNoise[] = {
    //crt
    "fwrite",
    "mainCRTStartup",
    "set_app_type",
    "initterm_e",
    "o___stdio_common_vswprintf",
    "towlower_l",
    "GetEnvironmentStringsW",
    "configure_narrow_argv",
    "get_wpgmptr",


    // ntdll loader
    "LdrLoadDll",
    "LdrControlFlowGuardEnforced",
    "LdrpLoadDll",
    "LdrGetDllHandleEx",
    "LdrGetProcedureAddress",
    "LdrGetProcedureAddressForCaller",
    "LdrInitializeThunk",
    "LdrpInitialize",
    "LdrpInitializeProcess",
    "LdrpRunInitializeRoutines",
    "LdrpCallInitRoutine",
    "LdrpLoadDllInternal",
    "LdrResolveDelayLoadedAPI",

    // ntdll string/table internals
    "RtlAnsiStringToUnicodeString",
    "RtlAddressInSectionTable",
    "RtlFlsSetValue",
    "RtlReleaseSRWLockExclusive",
    "RtlAddGrowableFunctionTable",
    "RtlUTF8ToUnicodeN",
    "RtlAppendUnicodeStringToString",
    "RtlInsertElementGenericTableFullAvl",
    "RtlInsertElementGenericTableAvl",
    "RtlDeleteElementGenericTableAvlEx",
    "RtlEncodeRemotePointer",
    "RtlRaiseException",
    "RtlReleaseSRWLockShared",
    "RtlDeactivateActivationContextUnsafeFast",

    // thread noise
    "_beginthreadex",
    "beginthreadex",
    "TpSetWaitEx",
    "TpReleaseWork",
    "TpWaitForWork",
    "TppWorkpExecuteCallback",
    "TppWorkerThread",
    "register_onexit_function",

    // ETW 
    "EtwEventWriteNoRegistration",
    "EtwEventWrite",
    "EtwEventRegister",

    //windows stuff
    "ClearCommError",
    "ArmFeatureUsageSubscriberFlushNotification",
    "AppPolicyGetWindowingModel",

    //kernelbase
    "SetUnhandledExceptionFilter",

    // locale / time
    "unlock_locales",
    "setsystime",

    nullptr
    };

    static const char* systemModules[] = {
        "dbghelp.dll",
        "USER32.dll",
        "SDL2.dll",
        "ig9icd64.dll",
        "igc64.dll",
        nullptr
    };
 
    static const char* userStackFrame[] = {
        "main",
        "wmain",
        "wWinMain",
        "DllMain",
        nullptr
    };

    int framesChecked = 0;
    
    for(int i = 0; i < rec.frames; i++)
    {   
        
        uintptr_t addr = (uintptr_t) rec.callStack[i];

        char* file = rec.fileName[i];
        char* stackFrame = rec.resolvedStack[i];
        char* module = rec.moduleName[i];
        char* moduleName = PathFindFileNameA(module);

        //printf("stack frame: %s\n", stackFrame);
        //printf("module name: %s\n", module);

        bool isNoise = false;
        for (int j = 0; systemNoise[j] != nullptr; j++)
        {
            if (strcmp(stackFrame, systemNoise[j]) == 0)
            {
                isNoise = true;
                break;
            }
        }

        if (isNoise) continue;

        if(_stricmp(moduleName, "ntleak.dll") == 0)
        {
            return false;
        }

        if (addr >= base && addr < end)
        {   
            //printf("user module name: %s\n", module);
            //printf("file name: %s\n", file);
            //printf("stack frame: %s\n", stackFrame);

            //modules belong to the exe - no need to check for system modules
            for (int j = 0; crtNoise[j] != nullptr; j++)
            {
                if (strcmp(stackFrame, crtNoise[j]) == 0)
                {   
                    //printf("filtered user stack frame: %s\n", stackFrame);
                    return false;
                }
            }
            //printf("passed stack frame: %s\n", stackFrame);
            framesChecked++;
        }

        else { 

            if (file)
            {
                if (strstr(file, "win_policies.cpp") || strstr(file, "stdio.cpp"))
                {
                    return false;
                }
            }

            for (int j = 0; externalNoise[j] != nullptr; j++)
            {
                if (_stricmp(stackFrame, externalNoise[j]) == 0)
                {   
                    //printf("filtered external stack frame: %s\n", stackFrame);
                    return false;
                }   
            }
            //printf("passed system stack frame: %s   , file name: %s   , module: %s \n", stackFrame, file, moduleName);

            //filter system modules
            for (int j = 0; systemModules[j] != nullptr; j++)
            {
                if (_stricmp(moduleName, systemModules[j]) == 0)
                {   
                    //printf("filtered system module: %s\n", stackFrame);
                    return false;
                }   
            }
            //printf("passed system module name : %s\n", module);

            framesChecked++;
        }

        // for user stackframes
        for (int j = 0; userStackFrame[j] != nullptr; j++)
        {
            if (strcmp(stackFrame, userStackFrame[j]) == 0)
            {   
                //printf("user stack frame detected: %s, module: %s \n", stackFrame, moduleName)
                return true;
            }
        }
    }
    
    return true;
}

void MemTracker::shutdown()
{   
    allocMap.cleanup();
    SymCleanup(hProcess);
    TlsFree(g_tlsHeapAlloc);
    TlsFree(g_tlsMalloc);
    TlsFree(g_tlsRealloc);
}

