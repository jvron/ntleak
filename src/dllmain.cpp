#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <atomic>

#include "hooks.h"
#include "tracker.h"

std::atomic<bool> g_Running; //global running flag
HANDLE g_hThread = NULL; //global thread handle

DWORD WINAPI MainThread(LPVOID lpParam)
{   
    tracker.trackingEnabled = false;
    tracker.trackFreeEnabled = false;

    MH_STATUS status;
    //printf("calling tracker.init\n"); fflush(stdout);
    tracker.init();
    //printf("calling initMinHook\n"); fflush(stdout);
    status = initMinHook();
    //printf("initMinHook status: %d\n", status); fflush(stdout);
    status = createHooks();
    //printf("createHooks status: %d\n", status); fflush(stdout);
    status = enableHooks();
    //printf("enableHooks status: %d\n", status); fflush(stdout);

    //opens the event created by the injector, gets the handle to the event
    HANDLE hReady = OpenEventA(EVENT_MODIFY_STATE, FALSE, "ntleak_hooks_ready");
    HANDLE hMDdTrue = OpenEventA(EVENT_MODIFY_STATE, FALSE, "ntleak_dynamic_debug_crt");

    if (tracker.linktype == DYNAMIC_DEBUG)
    {   
        //target compiled with /MDd produces false positives due to CRT debug allocations 
        MH_DisableHook(MH_ALL_HOOKS);
        MH_RemoveHook(MH_ALL_HOOKS);
        uninitMinHook();
        tracker.shutdown();

        if(hMDdTrue)
        {
            SetEvent(hMDdTrue); // signals the event
            CloseHandle(hMDdTrue);
        }
        return 1;
    }

    tracker.trackingEnabled = true;
    tracker.trackFreeEnabled = true;
    
    if(hReady)
    {
        SetEvent(hReady); // signals the event
        CloseHandle(hReady);
    }

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
        case DLL_PROCESS_ATTACH:

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

            //printf("DLL_PROCESS_DETACH fired, lpvReserved=%p\n", lpvReserved);
            //fflush(stdout);

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