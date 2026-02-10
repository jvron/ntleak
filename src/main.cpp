#include <windows.h>
#include <MinHook.h>
#include <cstddef>
#include <handleapi.h>
#include <iostream>
#include <stdlib.h>

#include "hooks.h"
#include "tracker.h"


int main(void)
{   

    tracker.init();

    tracker.trackingEnabled = false;
    
    if (MH_Initialize() != MH_OK)
    {   
        std::cout << "Init faild\n";
        return -1;
    }
    else {
        std::cout << "init success\n";
    }
    
    
    MH_STATUS status;
    status = hookHeapAlloc();
    status = hookHeapFree();
    status = hookVirtualAlloc();
    status = hookVirtualFree();
    
    //status = hookMalloc();
    //status = hookFree();

    tracker.trackingEnabled = true;
    
    //testing
    int *pX = (int*) malloc(sizeof(int));
    int *pY = (int*) malloc(sizeof(int));
    int *pZ = (int*) malloc(sizeof(long long));
    
    if (pX == NULL)
    {
        std::cout << "failed to allocate\n";
        return -1;
    }
    
    *pX = 8;
    *pY = 9;
    
    //std::cout << status << "\n"; 
    //std::cout << *pX << "\n";
    
    free(pX);

    tracker.trackingEnabled = false;
    status = removeHooks();
    
    if (MH_Uninitialize() != MH_OK)
    {
        return 1;
    }
    
    tracker.resolveSymbols();
    tracker.report();
    tracker.shutdown();

    return 0;
}
