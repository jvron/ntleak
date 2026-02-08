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

    //void* (*pMallocOriginal)(size_t size) = NULL;

    if (MH_Initialize() != MH_OK)
    {   
        std::cout << "Init faild\n";
        return -1;
    }
    else {
        std::cout << "init success\n";
    }

    tracker.init();

    
    MH_STATUS status;
    status = hookHeapAlloc();
    status = hookHeapFree();
    
    
    status = hookMalloc();
    status = hookFree();
    
    //testing
    int *pX = (int*) malloc(sizeof(int));
    int *pY = (int*) malloc(sizeof(int));
    
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
    
    
    status = removeHooks();
    
    if (MH_Uninitialize() != MH_OK)
    {
        return 1;
    }
    
    resolve(tracker);
    
    tracker.report();
    tracker.shutdown();

    

    return 0;
}
