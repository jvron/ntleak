#include <windows.h>
#include <atomic>
#include <synchapi.h>
#include <MinHook.h>
#include <cstdlib>
#include <minwinbase.h>
#include <minwindef.h>
#include <winnt.h>

#include "hooks.h"
#include "tracker.h"

std::atomic<bool> g_Running; //global running flag
HANDLE hThread = NULL;

DWORD WINAPI MainThread(LPVOID lpParam)
{   
    printf("mainThread running.... \n");
    MH_STATUS status;
    tracker.trackingEnabled = false;
    status = initMinHook();
    status = createHooks();
    status = enableHooks();
    tracker.trackingEnabled = true;

    printf("mainThread waiting outside loop.... \n");
    while (g_Running)
    { // wait for program to exit
       
        printf("mainThread waiting.... \n");
        Sleep(100);
    }

    tracker.trackingEnabled = false;

    status = disableHooks();
    status = removeHooks();
    status = uninitMinHook();

    tracker.resolveSymbols();
    tracker.report();
    tracker.shutdown();

    printf("mainThread exiting.... \n");

    return 0;
}

// entry point for dll 
BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD reason, LPVOID lpvReserved) 
{   
    
    switch (reason)
    {
        case DLL_PROCESS_ATTACH: //runs when dll is loaded into process

            g_Running = true;

            hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MainThread, NULL, 0, NULL);

            break;
        
        case DLL_THREAD_ATTACH:

        case DLL_THREAD_DETACH:

        case DLL_PROCESS_DETACH: //dll unloaded - program exiting
            g_Running = false;

            if(lpvReserved != nullptr) // process is terminating - dont run heavy funtions - causes deadlock
            {
                break; 
            }
            else  // FreeLibrary is called - process is still running
            {
                // safe to clean up
            }
        
        break;
    }
    return TRUE;
}