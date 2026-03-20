#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <filesystem>
#include <iostream>
#include <string>

#include "tracker.h"
#include "alloc_map.h"

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cerr << "Error: no target executable specified.\n";
        std::cerr << "Usage: ntleak <path_to_executable>\n";
        return -1;
    }

    char* exeName = argv[1];
    
    std::filesystem::path cwd = std::filesystem::current_path();
    std::string exePath = cwd.string() + "\\" + exeName;
    char *cmd = exePath.data();

    //char dllPath[MAX_PATH] = "C:\\Dev\\ntleak\\build_release\\Release\\ntleak.dll";
    char dllPath[MAX_PATH] = "C:\\Dev\\ntleak\\build\\Debug\\ntleak.dll";

    PROCESS_INFORMATION procInfo;
    STARTUPINFOA startInfo;
    ZeroMemory(&startInfo, sizeof(startInfo));
    startInfo.cb = sizeof(STARTUPINFOA);

    BOOL result = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startInfo, &procInfo);

    if (result) 
    {   
        //std::cout << "Child launched. Waiting...\n";
        DWORD procId = procInfo.dwProcessId;
        HANDLE hProc = procInfo.hProcess;
        HANDLE hThread = procInfo.hThread;
        
        HANDLE hMapFile = NULL;
        HANDLE hRThread = NULL;

        HANDLE hReady = CreateEventA(NULL, TRUE, FALSE, "ntleak_hooks_ready");
        HANDLE hMDdTrue =  CreateEventA(NULL, TRUE, FALSE, "ntleak_dynamic_debug_crt");
        
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
            std::cerr << "remote thread creation failed. Error: " << GetLastError() << std::endl;
            return -1;
        }

        //wait for dll to load
        WaitForSingleObject(hRThread, INFINITE);
        //printf("LoadLibrary finished\n");


        HANDLE events[2] = {hReady, hMDdTrue};
        //wait for hooks to initialze or if the target is compiled with /MDd 
        DWORD eventResult = WaitForMultipleObjects(2, events, FALSE, INFINITE);

        if (eventResult == WAIT_OBJECT_0 + 1) //if hMDdTrue is flagged 
        {
            std::cerr << "[ntleak] ERROR: Target compiled with /MDd (debug CRT). ntleak does not support /MDd.\n";
            TerminateProcess(hProc, 1);
            if (hRThread)
            {
                CloseHandle(hRThread);
            }

            CloseHandle(hMDdTrue);
            CloseHandle(hProc);
            CloseHandle(hThread);
            
            return 1;
        }
        else {
            //continue if hooks are ready 
            CloseHandle(hReady);
            CloseHandle(hMDdTrue);
        }

        hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, "ntleak_allocation_table");

        if (hMapFile == NULL)
        {
            std::cerr << "Could not open file mapping object. Error code: "<<  GetLastError() << std::endl;
            return 1;
        }
                
        //resume thread
        ResumeThread(procInfo.hThread);
        //printf("Thread resumed\n");
        
        //wait for process to exit
        WaitForSingleObject(hProc, INFINITE);
        //printf("Child process exited \n");

        DWORD exitCode = 0;
        GetExitCodeProcess(hProc, &exitCode);
        std::cout << "Child process exited with code: " << exitCode << std::endl;

        //access shared memory, resolve symbols, report and shutdown
        tracker.trackingEnabled = false;
        AllocRecord *sharedMem = (AllocRecord*) MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS,  0,  0, HashTable::hashGroups * sizeof(AllocRecord));
        
        if (sharedMem == NULL)
        {
            std::cerr << "unable to access shared memory. Error code: " <<  GetLastError() << std::endl;
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
        std::cerr << "Failed to launch process. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    return 0;
}

