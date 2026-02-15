#include <MinHook.h>
#include <cstddef>
#include <cstdlib>
#include <heapapi.h>
#include <memoryapi.h>
#include <minwindef.h>
#include <stdio.h>
#include <winnt.h>

#include "hooks.h"
#include "tracker.h"

//function pointers that points to the original funtion. MinHook will store the target functions in these function pointers
void* (*pMallocOriginal)(size_t size) = NULL;
void (*pFreeOriginal)(void* ptr) = NULL;

void* (*pReallocOriginal)(void* memptr, size_t size) = NULL;

void* (*pOperatorNewOriginal) (size_t size) = NULL;
void (*pOperatorDeleteOriginal)(void* ptr) = NULL;

void* (*pOperatorNewArrayOriginal) (size_t size) = NULL;
void (*pOperatorDeleteArrayOriginal)(void* ptr) = NULL;

LPVOID (*pHeapAllocOriginal)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) = NULL;
BOOL (*pHeapFreeOriginal) (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) = NULL;

LPVOID (*pHeapReAllocOriginal) (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes) = NULL;

LPVOID (*pVirtualAllocOriginal) (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = NULL;
BOOL (*pVirtualFreeOriginal) (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) = NULL; 

//tls flags
thread_local bool inMalloc = false;
thread_local bool inRealloc = false;
thread_local bool inOperatorNew = false;

MH_STATUS initMinHook()
{
    MH_STATUS status;
    status = MH_Initialize();
    if(status != MH_OK) return status;
    return status;
}
MH_STATUS uninitMinHook()
{
    MH_STATUS status;
    status = MH_Uninitialize();
    if(status != MH_OK) return status;
    return status;
}

void* detourMalloc(size_t size)
{   
    inMalloc = true;

    void *memptr = pMallocOriginal(size);

    if (memptr != NULL && !inOperatorNew)
    {
        tracker.trackAlloc(size, memptr);
    };

    //printf("malloc returned: %p\n", memptr);
    inMalloc = false;
    return memptr;
}

void detourFree(void *ptr)
{   
    pFreeOriginal(ptr);
    tracker.trackFree(ptr);
    //printf("free called at: %p\n", ptr);
}

void* detourRealloc(void *memptr, size_t size)
{   
    inRealloc = true;
    void* newptr = pReallocOriginal(memptr, size);

    if(newptr != NULL)
    {   
        if (memptr == NULL) //same as malloc
        {
            tracker.trackAlloc(size, newptr);
        }

        else if (newptr != memptr) // new pointer returned by realloc, old ptr freed
        {
            tracker.trackFree(memptr);
            tracker.trackAlloc(size, newptr);
        }
        
        else if (newptr == memptr)
        {
            tracker.trackAlloc(size, memptr); // replace the old allocation with new size
        }
    }
    else { // newptr == NULL

        if (size == 0)
        {
            // same as free
            tracker.trackFree(memptr);
        }
    }


    //printf("realloc called at: %p\n", memptr);
    //printf("realloc returned: %p\n", newptr);
    inRealloc = false;
    return newptr;
}

void* detourOperatorNew(size_t size)
{   
    inOperatorNew = true;
    void* memptr = pOperatorNewOriginal(size);
    //std::bad_alloc is automatically handled

    if(memptr != nullptr) // in case new is called with nothrow 
    {
        tracker.trackAlloc(size, memptr);
    }

    inOperatorNew = false;
    return memptr;
}

void detourOperatorDelete(void *ptr)
{
    pOperatorDeleteOriginal(ptr);
    tracker.trackFree(ptr);
}

void* detourOperatorNewArray(size_t size)
{   
    inOperatorNew = true;
    void* memptr = pOperatorNewArrayOriginal(size);
    //std::bad_alloc is automatically handled

    tracker.trackAlloc(size, memptr);

    inOperatorNew = false;
    return memptr;
}

void detourOperatorDeleteArray(void *ptr)
{
    pOperatorDeleteArrayOriginal(ptr);
    tracker.trackFree(ptr);
}

LPVOID detourHeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    void* memptr = pHeapAllocOriginal(hHeap, dwFlags, dwBytes);
    
    if (memptr != NULL && !inMalloc && !inRealloc) // do not track heapAlloc triggered by malloc and realloc
    {   
        tracker.trackAlloc(dwBytes, memptr);
        //printf("HeapAlloc tracked at: %p\n", hHeap);
    } 

    return memptr;
}

BOOL detourHeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    BOOL result = pHeapFreeOriginal(hHeap, dwFlags, lpMem);

    if (result != 0)
    {
        tracker.trackFree(lpMem);
    }

    return result;
}

LPVOID detourHeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
{
    
    void* newptr = pHeapReAllocOriginal(hHeap, dwFlags, lpMem, dwBytes);

    if(newptr != NULL)
    {   
        if (!inRealloc &&! inMalloc)
        {
            if (lpMem == NULL) //same as HeapAlloc
            {
                tracker.trackAlloc(dwBytes, newptr);
            }
            else if (newptr != lpMem) // new pointer returned by HeapReAlloc, old ptr freed
            {
                tracker.trackFree(lpMem);
                tracker.trackAlloc(dwBytes, newptr);
            }
            else if (newptr == lpMem)
            {
                tracker.trackAlloc(dwBytes, lpMem); // replace the old allocation with new size
            }
        }
    }
    else  {
        if (dwBytes == 0 && !inRealloc &&! inMalloc)
        {
            tracker.trackFree(lpMem);
        }
    }

    //printf("HeapReAlloc called at: %p\n", memptr);
    //printf("HeapReAlloc returned: %p\n", newptr);
    return newptr;
}

PVOID detourVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    void* memptr = pVirtualAllocOriginal(lpAddress, dwSize, flAllocationType, flProtect);

    if (memptr != NULL)
    {
        tracker.trackAlloc(dwSize, memptr);
    }
    return memptr;
}

BOOL detourVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    BOOL result = pVirtualFreeOriginal(lpAddress, dwSize, dwFreeType);

    if (result != 0)
    {
        tracker.trackFree(lpAddress);
    }

    return result;
}

MH_STATUS hookMalloc()
{
    MH_STATUS status;

    status = MH_EnableHook((void*)&malloc);
    if (status != MH_OK)
    {
        return status;
    }
    return status;
}

MH_STATUS hookFree()
{
    MH_STATUS status;

    status = MH_EnableHook((void*)&free);
    if (status != MH_OK)
    {
        return status;
    }

    return status;
}

MH_STATUS hookRealloc()
{
    MH_STATUS status;

    status = MH_EnableHook((void*)&realloc);
    if (status != MH_OK)
    {
        return status;
    }

    return status;
}

MH_STATUS hookOperatorNew()
{
    MH_STATUS status;
    //(void* (*)(std::size_t)) &operator new;

    status = MH_EnableHook((void*)(void* (*)(std::size_t)) &operator new);
    if (status != MH_OK)
    {
        return status;
    }
    return status;
}

MH_STATUS hookOperatorDelete()
{
    MH_STATUS status;

    //(void*)(void (*)(void*)) &operator delete

    status = MH_EnableHook((void*)(void*)(void (*)(void*)) &operator delete);
    if (status != MH_OK)
    {
        return status;
    }
    
    return status;
}

MH_STATUS hookOperatorNewArray()
{
    MH_STATUS status;
    //(void* (*)(std::size_t)) &operator new[]

    status = MH_EnableHook((void*)(void* (*)(std::size_t)) &operator new[]);
    if (status != MH_OK)
    {
        return status;
    }
    return status;
}

MH_STATUS hookOperatorDeleteArray()
{
    MH_STATUS status;

    //(void*)(void (*)(void*)) &operator delete[]

    status = MH_EnableHook((void*)(void*)(void (*)(void*)) &operator delete[]);
    if (status != MH_OK)
    {
        return status;
    }
    
    return status;
}

MH_STATUS hookHeapAlloc()
{
    MH_STATUS status;

    status = MH_EnableHook((void*)&HeapAlloc);
    if (status != MH_OK)
    {
        return status;
    }

    return status;
}

MH_STATUS hookHeapReAlloc()
{
    MH_STATUS status;

    status = MH_EnableHook((void*)&HeapReAlloc);
    if (status != MH_OK)
    {
        return status;
    }

    return status;
}

MH_STATUS hookVirtualAlloc()
{
    MH_STATUS status;

    status = MH_EnableHook((void*)&VirtualAlloc);
    if (status != MH_OK)
    {
        return status;
    }

    return status;
}

MH_STATUS hookHeapFree()
{
    MH_STATUS status;

    status = MH_EnableHook((void*)&HeapFree);
  
    if (status != MH_OK)
    {
        return status;
    }
    
    return status;
}

MH_STATUS hookVirtualFree()
{
    MH_STATUS status;
    status = MH_EnableHook((void*)&VirtualFree);
  
    if (status != MH_OK)
    {
        return status;
    }
    
    return status;
}

MH_STATUS createHooks()
{
    MH_STATUS status;

    //malloc
    status = MH_CreateHook((void*)&malloc, (void*) &detourMalloc, reinterpret_cast<LPVOID*>(&pMallocOriginal));
    if(status != MH_OK)
    {
        return status;
    }
    //free
    status = MH_CreateHook((void*)&free, (void*) &detourFree, reinterpret_cast<LPVOID*>(&pFreeOriginal));

    if(status != MH_OK)
    {
        return status;
    }
    //realloc
    status = MH_CreateHook((void*)&realloc, (void*) &detourRealloc, reinterpret_cast<LPVOID*>(&pReallocOriginal));

    if(status != MH_OK)
    {
        return status;
    }
    //operator new
    status = MH_CreateHook((void*)(void* (*)(std::size_t)) &operator new, (void*) &detourOperatorNew, reinterpret_cast<LPVOID*>(&pOperatorNewOriginal));
    if(status != MH_OK)
    {
        return status;
    }
    //operator delete
    status = MH_CreateHook((void*)(void (*)(void*)) &operator delete, (void*) &detourOperatorDelete, reinterpret_cast<LPVOID*>(&pOperatorDeleteOriginal));

    if(status != MH_OK)
    {
        return status;
    }
    //operator new[]
    status = MH_CreateHook((void*)(void* (*)(std::size_t)) &operator new[], (void*) &detourOperatorNewArray, reinterpret_cast<LPVOID*>(&pOperatorNewArrayOriginal));
    if(status != MH_OK)
    {
        return status;
    }
    //operator delete[]
    status = MH_CreateHook((void*)(void (*)(void*)) &operator delete[], (void*) &detourOperatorDeleteArray, reinterpret_cast<LPVOID*>(&pOperatorDeleteArrayOriginal));

    if(status != MH_OK)
    {
        return status;
    }
    //heapalloc
    status = MH_CreateHook((void*)&HeapAlloc, (void*) &detourHeapAlloc, reinterpret_cast<LPVOID*>(&pHeapAllocOriginal));
    if(status != MH_OK)
    {
        return status;
    }
    //heaprealloc
    status = MH_CreateHook((void*)&HeapReAlloc, (void*) &detourHeapReAlloc, reinterpret_cast<LPVOID*>(&pHeapReAllocOriginal));

    if(status != MH_OK)
    {
        return status;
    }
    //virtual alloc
    status = MH_CreateHook((void*)&VirtualAlloc, (void*) &detourVirtualAlloc, reinterpret_cast<LPVOID*>(&pVirtualAllocOriginal));

    if(status != MH_OK)
    {
        return status;
    }

    //heapfree
    status = MH_CreateHook((void*)&HeapFree, (void*) &detourHeapFree, reinterpret_cast<LPVOID*>(&pHeapFreeOriginal));

    if(status != MH_OK)
    {
        return status;
    }
    //virtualfree
    status = MH_CreateHook((void*)&VirtualFree, (void*) &detourVirtualFree, reinterpret_cast<LPVOID*>(&pVirtualFreeOriginal));

    if(status != MH_OK)
    {
        return status;
    }

    return status;
}

MH_STATUS enableHooks()
{
    MH_STATUS status;
    
    status = hookHeapAlloc();
    if(status != MH_OK) return status;

    status = hookHeapFree();
    if(status != MH_OK) return status;

    status = hookHeapReAlloc();
    if(status != MH_OK) return status;

    status = hookRealloc();
    if(status != MH_OK) return status;

    status = hookVirtualAlloc();
    if(status != MH_OK) return status;

    status = hookVirtualFree();
    if(status != MH_OK) return status;
    
    status = hookMalloc();
    if(status != MH_OK) return status;

    status = hookFree();
    if(status != MH_OK) return status;

    status = hookOperatorNew();
    if(status != MH_OK) return status;

    status = hookOperatorDelete();
    if(status != MH_OK) return status;

    status = hookOperatorNewArray();
    if(status != MH_OK) return status;
    status = hookOperatorDeleteArray();
    if(status != MH_OK) return status;

    return status;
}

MH_STATUS disableHooks()
{
    MH_STATUS status;

    status = MH_DisableHook((void*)&malloc);
    if (status != MH_OK) return status;

    status = MH_DisableHook((void*)&free);
    if (status != MH_OK) return status;

    status = MH_DisableHook((void*)&HeapAlloc);
    if (status != MH_OK) return status;

    status = MH_DisableHook((void*)&HeapFree);
    if (status != MH_OK) return status;

    status = MH_DisableHook((void*)&realloc);
    if(status != MH_OK) return status;

    status = MH_DisableHook((void*)&HeapReAlloc);
    if(status != MH_OK) return status;

    status = MH_DisableHook((void*)(void* (*)(std::size_t)) &operator new);
    if(status != MH_OK) return status;

    status = MH_DisableHook((void*)(void (*)(void*)) &operator delete);
    if(status != MH_OK) return status;

    status = MH_DisableHook((void*)(void* (*)(std::size_t)) &operator new[]);
    if(status != MH_OK) return status;

    status = MH_DisableHook((void*)(void (*)(void*)) &operator delete[]);
    if(status != MH_OK) return status;

    return status;
}

MH_STATUS removeHooks()
{   
    MH_STATUS status;

    status = MH_RemoveHook((void*)&malloc);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)&free);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)&HeapAlloc);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)&HeapFree);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)&VirtualAlloc);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)&VirtualFree);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)&realloc);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)(void* (*)(std::size_t)) &operator new);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)(void (*)(void*)) &operator delete);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)(void* (*)(std::size_t)) &operator new[]);
    if(status != MH_OK) return status;

    status = MH_RemoveHook((void*)(void (*)(void*)) &operator delete[]);
    if(status != MH_OK) return status;

    return status;
}
