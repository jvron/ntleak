#include <windows.h>
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



int main(int argc, char* argv[])
{
    
    if (argc < 2)
    {
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

    //printf("the current working dir is %s\n", cwd);

    PROCESS_INFORMATION procInfo;
    STARTUPINFOA startInfo;

    ZeroMemory(&startInfo, sizeof(startInfo));
    startInfo.cb = sizeof(STARTUPINFOA);

    std::string backslash = "\\";

    std::string exePath = cwd + backslash + exeName;

    char *cmd = exePath.data();

    char dllPath[MAX_PATH] = "C:\\Dev\\ntleak\\build_release\\Release\\ntleak.dll";

    BOOL result = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startInfo, &procInfo);

    if (result) 
    {
        std::cout << "Child launched. Waiting...\n";
        //WaitForSingleObject(procInfo.hProcess, INFINITE);

        DWORD procId = procInfo.dwProcessId;
        HANDLE hProc = procInfo.hProcess;

        //allocate memory for dllPath inside the target process - VirtualAllocEx allocates memory in externel process
        void* memptr = VirtualAllocEx(hProc, NULL, sizeof(dllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (memptr == NULL)
        {
            return -1;
        }

        //write the dllPath into the target process memeory
        WriteProcessMemory(hProc, memptr, dllPath, strlen(dllPath) + 1, 0);

        //create remote thread in target process that calls LoadLibraryA, the parameter passed to LoadLibrary is memptr which has our dllPath, so it becomes LoadLibraryA(dllPath)
        HANDLE hRThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, memptr, 0, 0);

        if (hRThread == NULL)
        {
            printf("remote thread creation failed. Error: %lu\n", GetLastError());
        }

        //wait for hRThread to finish execution - wait for LoadLibraryA to load dll
        WaitForSingleObject(hRThread, INFINITE);

        DWORD exitCode;
        GetExitCodeThread(hRThread, &exitCode);

        printf("hRThread exit code: %lu\n", exitCode);

        ResumeThread(procInfo.hThread);

        //wait for process to exit
        WaitForSingleObject(hProc, INFINITE);
        printf("child process exited \n");

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

