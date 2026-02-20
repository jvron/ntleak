#include <windows.h>
#include <errhandlingapi.h>
#include <memoryapi.h>
#include <debugapi.h>
#include <minwinbase.h>
#include <synchapi.h>
#include <cstdio>
#include <libloaderapi.h>
#include <minwindef.h>
#include <cstring>
#include <cstdlib>
#include <processthreadsapi.h>
#include <MinHook.h>
#include <cstddef>
#include <handleapi.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <winnt.h>

#include "tracker.h"
#include "alloc_map.h"


int main(int argc, char* argv[])
{
    tracker.trackingEnabled = false;

    if (argc < 2)
    {
        printf("Error: no target executable specified.\n");
        printf("Usage: ntleak <path_to_executable>\n");
        return -1;
    }

    char* exeName = argv[1];
    
    char cwd[MAX_PATH];

    DWORD cwdRes = GetCurrentDirectory(MAX_PATH, cwd);

    if (cwdRes == 0)
    {
        printf("GetCurrentDirectory failed %lu\n", GetLastError());
        return -1;
    }

    if(cwdRes > MAX_PATH)
    {
        printf("Buffer too small; need %lu characters\n", cwdRes);
        return -1;
    }


    PROCESS_INFORMATION procInfo;
    STARTUPINFOA startInfo;

    ZeroMemory(&startInfo, sizeof(startInfo));
    startInfo.cb = sizeof(STARTUPINFOA);

    std::string backslash = "\\";

    std::string exePath = cwd + backslash + exeName;

    char *cmd = exePath.data();

    char dllPath[MAX_PATH] = "C:\\Dev\\ntleak\\build\\Debug\\ntleak.dll";

    BOOL result = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startInfo, &procInfo);

    if (result) 
    {   
        std::cout << "Child launched. Waiting...\n";
        DWORD procId = procInfo.dwProcessId;
        HANDLE hProc = procInfo.hProcess;
        
        HANDLE hMapFile = NULL;
        HANDLE hRThread = NULL;

        HANDLE hReady = CreateEventA(NULL, TRUE, FALSE, "ntleak_hooks_ready");
        
        //allocate memory for dllPath inside the target process - VirtualAllocEx allocates memory in externel process
        void* memptr = VirtualAllocEx(hProc, NULL, sizeof(dllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if (memptr == NULL)
        {
            return -1;
        }
        //write the dllPath into the target process memeory
        WriteProcessMemory(hProc, memptr, dllPath, strlen(dllPath) + 1, 0);
        
        //create remote thread in target process that calls LoadLibraryA, the parameter passed to LoadLibrary is memptr which has our dllPath,
        hRThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, memptr, 0, 0);
        
        if (hRThread == NULL)
        {
            printf("remote thread creation failed. Error: %lu\n", GetLastError());
            return -1;
        }

        //wait for dll to load
        WaitForSingleObject(hRThread, INFINITE);
        printf("LoadLibrary finished\n");


        //wait for hooks to initialize
        WaitForSingleObject(hReady, INFINITE);
        CloseHandle(hReady);

        hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, "ntleak_allocation_table");

        if (hMapFile == NULL)
        {
            printf("Could not open file mapping object (%lu).\n", GetLastError());
            return 1;
        }
                
        //resume thread
        ResumeThread(procInfo.hThread);
        printf("Thread resumed\n");
        
        //wait for process to exit
        WaitForSingleObject(hProc, INFINITE);
        printf("child process exited \n");

        DWORD exitCode = 0;
        GetExitCodeProcess(hProc, &exitCode);
        printf("Exit code: %lu\n", exitCode);

        //access shared memory, resolve symbols, report and shutdown
        tracker.trackingEnabled = false;
        AllocRecord *sharedMem = (AllocRecord*) MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS,  0,  0, HashTable::hashGroups * sizeof(AllocRecord));
        
        if (sharedMem == NULL)
        {
            printf("unable to access shared memory. Error code: %lu", GetLastError());
            return -1;
        }
        
        tracker.allocMap.table = sharedMem;

        //do stuff with allocations 
        
        UnmapViewOfFile(sharedMem);
        CloseHandle(hMapFile);

        if (hRThread)
        {
            CloseHandle(hRThread);
        }
        CloseHandle(procInfo.hProcess);
        CloseHandle(procInfo.hThread);
    } 
    else {

        std::cerr << "Failed to launch process. Error: " << GetLastError() << "\n";
    }

    return 0;
}

