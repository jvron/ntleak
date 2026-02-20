#include <windows.h>
#include <handleapi.h>
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
HANDLE g_hThread = NULL; //global thread handle

DWORD WINAPI MainThread(LPVOID lpParam)
{   
    tracker.trackingEnabled = false;

    printf("mainThread running.... \n");
    MH_STATUS status;
    //printf("calling tracker.init\n"); fflush(stdout);
    tracker.init();
    //printf("calling initMinHook\n"); fflush(stdout);
    status = initMinHook();
    //printf("initMinHook status: %d\n", status); fflush(stdout);
    status = createHooks();
    printf("createHooks status: %d\n", status); fflush(stdout);
    status = enableHooks();
    printf("enableHooks status: %d\n", status); fflush(stdout);
    
    //printf("hooked malloc address: %p\n", malloc);

    //opens the event created by the injector, gets the handle to the event

    HANDLE hReady = OpenEventA(EVENT_MODIFY_STATE, FALSE, "ntleak_hooks_ready");

    if(hReady)
    {
        SetEvent(hReady); // signals the event
        CloseHandle(hReady);
    }
    tracker.trackingEnabled = true;

    //int *pX = (int*) malloc(20);

    //printf("mainThread waiting outside loop.... \n");
    //fflush(stdout);

    while(g_Running)
    {
        Sleep(100);
    }

    tracker.trackingEnabled = false;

    return 0;
}

// entry point for dll 
BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD reason, LPVOID lpvReserved) 
{   
    
    switch (reason)
    {
        case DLL_PROCESS_ATTACH: //runs when dll is loaded into process

            //diable dllMain calls for thread attach and detach
            DisableThreadLibraryCalls(hinstDLL);
            g_Running = true;

            g_hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MainThread, NULL, 0, NULL);

            break;
        
        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;

        case DLL_PROCESS_DETACH: //dll unloaded - program exiting
            g_Running = false;
            printf("DLL_PROCESS_DETACH fired, lpvReserved=%p\n", lpvReserved);
            fflush(stdout);

            if(lpvReserved != nullptr) // process is terminating - dont run heavy funtions - causes deadlock
            {
                break;
            }
            else  // FreeLibrary is called - process is still running -  safe to clean up
            {   
                break;
                
            }
        
        break;
    }
    return TRUE;
}