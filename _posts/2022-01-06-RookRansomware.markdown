---
title: Rook Ransomware
categories:
  - Reverse Engineering
description: Malware Analysis Report - Rook Ransomware
---

# Rook Ransomware

## Contents

- [Rook Ransomware](#rook-ransomware)
  - [Contents](#contents)
  - [Overview](#overview)
  - [IOCS](#iocs)
  - [Ransom Note](#ransom-note)
- [Static Code Analysis](#static-code-analysis)
  - [RSA Key Generation](#rsa-key-generation)
  - [Anti-Detection: Alternate Data Streams](#anti-detection-alternate-data-streams)
  - [Command-line Arguments](#command-line-arguments)
  - [Logging](#logging)
  - [Stopping Services](#stopping-services)
  - [Terminating Processes](#terminating-processes)
  - [Deleting Shadow Copies](#deleting-shadow-copies)
  - [Multithreading Setup](#multithreading-setup)
  - [Network Resource Traversal](#network-resource-traversal)
  - [Drives Traversal](#drives-traversal)
  - [Shares Traversal](#shares-traversal)
  - [Child Thread](#child-thread)
  - [File Encryption](#file-encryption)
  - [References](#references)

## Overview

This is my analysis for **ROOK Ransomware**.

**ROOK** is a relatively new ransomware that has been coming up in the last few months. With the [Mbed TLS library](https://github.com/ARMmbed/mbedtls), the malware uses a hybrid cryptography scheme to encrypt files using AES and protect its keys with RSA-2048.

For execution speed, **ROOK** is quite fast since it uses a decently good method of multithreading with two global lists for file and directory traversal.

As it has been claimed by other researchers, **ROOK** borrows some of the code from the leaked **BABUK** source code. To be more specific, the **ROOK** developers copied and pasted the code for services & processes termination as well as deleting shadow copies. **ROOK's** multithreading approach is a reimplementation and an upgrade from that of **BABUK version 3**, which is now more efficient for directory traversal.

However, unlike **BABUK** devs who are big fans of using ECDH curves and eSTREAM portfolio Profile 1 ciphers such as ChaCha and HC-128 for hybrid-encryption, **ROOK** devs stick with the traditional choice of RSA and AES.

![alt text](/uploads/rook01.PNG)

*Figure 1: ROOK Leak Site.*

## IOCS

The analyzed sample is a 64-bit Windows executable.

**MD5**: 6d87be9212a1a0e92e58e1ed94c589f9

**SHA256**: c2d46d256b8f9490c9599eea11ecef19fde7d4fdd2dea93604cee3cea8e172ac

**Sample**: [MalwareBazaar](https://bazaar.abuse.ch/sample/c2d46d256b8f9490c9599eea11ecef19fde7d4fdd2dea93604cee3cea8e172ac/)

![alt text](/uploads/rook02.PNG)

*Figure 2: VirusTotal Result.*

## Ransom Note

The content of the default ransom note is stored in plaintext in **ROOK's** executable.

**ROOK's** ransom note filename is **"HowToRestoreYourFiles.txt"**, which is really similar to **BABUK's "How To Restore Your Files.txt"**.

![alt text](/uploads/rook03.PNG)

*Figure 3: ROOK's Ransom Note.*

# Static Code Analysis

## RSA Key Generation

The first thing **ROOK** does upon execution is setting up the RSA keys for asymmetric encryption.

First, the malware initializes a **CTR_DRBG** [context](https://tls.mbed.org/api/structmbedtls__ctr__drbg__context.html) using the [Mbed TLS library](https://tls.mbed.org/api/ctr__drbg_8h.html), which is used to build a pseudo-RNG to later randomly generate AES keys.

![alt text](/uploads/rook04.PNG)

*Figure 4: CTR_DRBG Initialization.*

Next, it calls [mbedtls_pk_parse_public_key](https://tls.mbed.org/api/pk_8h.html#ade680bf8e87df7ccc3bb36b52e43972b) to parse the TA's RSA public key into a **mbedtls_pk_context** struct. The **ROOK's** public key context is then extracted from the **pk_ctx** field on the newly populated **mbedtls_pk_context** struct.

Below is the raw content of the public key.

``` RSA
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4g06WvN+BRr9GeeOkZ4y
nnK1uHreCPZyEsc43g3ftVXqsq2Kbdy7Z+XORqxmBi8D5nhDfw3eHRzH8wpcUos3
szWKyJLOeKhN6DM5M4FppD8hyuKDTcgsa70Nhapc1Oyjfh3kf3Kc/2CUhnPYEzHe
fHN3yOq9wxOVGc1S+bcTM3ez8gRuv0fB9ao2bJM0pKJphYq5dNkT0p2Ty923n+yZ
AOKELIWwwyOQgyfiv8ZwkdPL+UbNQq2dYZEWa1qSsGgN2655hvvD/pH/bggAFEqm
OybQFnRcdG9Fja9m/ZVp7jBYuX+4FaFq3DjD0oW/7imboVsEqcx7l7ym4tiKCz57
MwIDAQAB
-----END PUBLIC KEY-----
```

![alt text](/uploads/rook05.PNG)

*Figure 5: Parsing **ROOK's** RSA Public Key.*

**ROOK** then calls **RegCreateKeyExW** to open the subkey **Software** in **HKEY_CURRENT_USER**. Using that, it calls **RegQueryValueExW** to check if the registry value **RookPublicKey** exists in there. If it does not, the malware generates a public-private key pair for the victim.

![alt text](/uploads/rook06.PNG)

![alt text](/uploads/rook07.PNG)

*Figure 6, 7: Querying From Registry & Generating Victim Public-Private Key Pair.*

Next, **ROOK** encrypts the victim's RSA private key using its own public key context.

![alt text](/uploads/rook08.PNG)

*Figure 8: Encrypting Victim Private Key Using TA's Public Key.*

The victim's public key and encrypted private key are consecutively stored in the registry at the value **RookPublicKey** and **RookPrivateKey**.

If the victim's public key was already generated before and the malware can query it directly from registry, the victim's encrypted private key is pulled from the registry value **RookPrivateKey**.

Finally, the malware calls **mbedtls_pk_parse_public_key** to retrieve the victim's public key context and wipes the victim's raw private key from memory.

![alt text](/uploads/rook09.PNG)

*Figure 9: Writing Keys to Registry & Cleaning Up.*

## Anti-Detection: Alternate Data Streams

**Alternate Data Streams (ADS)** is a file attribute on the NT File System (NTFS) which was designed for compatibility with Macintosh Hierarchical File System (HFS).

For normal files, there is typically one primary data stream that is known as the unnamed data stream since its name is an empty string. However, ADS allows files to have more than one data stream, with any stream with a name being considered alternate.

Because alternate data streams are hidden from **Windows Explorer** and the **dir** command on the command-line, they are a sneaky way to hide external executable from a seemingly harmless file. 

To evade detection, **ROOK** uses ADS to hides its own executable. First, it calls **GetModuleFileNameW** with a NULL handle to retrieve its own executable path.

It then calls **CreateFileW** to retrieve its own handle and **SetFileInformationByHandle** to rename the file with a data stream named **":ask"**. This ultimately puts the entire executable into the alternate **":ask"** data stream, leaving an empty file on the primary stream.

![alt text](/uploads/rook10.PNG)

*Figure 10: Moving Executable to Data Stream.*

Pausing the execution after the handle is released using the call to **CloseHandle**, we can examine how it looks in the system.

By running the command **"dir /r"**, we can examine what changes to the executable file.

To test this, I use two copies of the **ROOK** sample and have the **ro0k.mal_** one hide itself in the **":ask"** data stream. As we can see in the command-line, that file shows up empty, but its alternate data stream contains the full malicious executable.

![alt text](/uploads/rook11.PNG)

*Figure 11: Examining Alternate Data Stream In Command-Line.*

After doing this, the ransomware file will appear as empty in the file system until the end of execution.

After hiding itself, **ROOK** also calls **SetFileInformationByHandle** again to set the file to be deleted once all handles are closed at the end.

![alt text](/uploads/rook12.PNG)

*Figure 12: Set Up File for Self-Deletion.*

## Command-line Arguments

**ROOK** can run with or without command-line arguments.

Below is the list of arguments that can be supplied by the operator.

| Argument   | Description |
| -------- | ----------- |
|**-debug \<log_filename\>**| Enable logging to the specified log file |
|**-shares \<share_list\>**| List of network shares to be traversed |
|**-paths \<drive_list\>**| List of local & network drives to be traversed |

## Logging

When the **debug** argument is provided on the command-line, **ROOK** enables debugging and calls **CreateFileW** to create the log file to later log into.

It also calls **InitializeCriticalSection** to initialize a critical section to prevent multiple threads from writing into the log file at the same time.

![alt text](/uploads/rook13.PNG)

*Figure 13: Logging Initialization.*

## Stopping Services

For stopping services, **ROOK** borrows this part from the leaked **BABUK** source code.

The malware first calls **GetTickCount** to get a tick count prior to stopping services. It then calls **OpenSCManagerA** to retrieve a service control manager handle.

![alt text](/uploads/rook14.PNG)

*Figure 14: Retrieving Service Control Manager.*

Next, it iterates through a hard-coded list containing services to be stopped. For each of these service, the malware calls **OpenServiceA** to retrieve the service's handle and **QueryServiceStatusEx** to query and checks if the service state is **SERVICE_STOP_PENDING**.

If it is not, **ROOK** calls **EnumDependentServicesA** to enumerate through all dependent services of the target service and stop them.

![alt text](/uploads/rook15.PNG)

*Figure 15: Iterating Through Service Stop List.*

For each dependent service, the malware calls **OpenServiceA** to retrieve its handle and **ControlService** to send a control stop code to stop it. It also sleeps and calls **QueryServiceStatusEx** to wait until the service's state is fully stopped.

![alt text](/uploads/rook16.PNG)

*Figure 16: Stopping Dependent Services.*

After stopping all dependent services, **ROOK** calls **ControlService** send a control stop code to the main service and continuosly checks until the service is fully stopped.

![alt text](/uploads/rook17.PNG)

*Figure 17: Stopping Target Services.*

For stopping all services, the maximum timeout is 30000ms or 30 seconds from the original tick count. If it takes more than 30 seconds to stop services, the malware aborts and exits the function.

Below is the list of services that are stopped.

``` c
"memtas", "mepocs", "vss", "sql", "svc$", "veeam", "backup", "GxVss", "GxBlr", "GxFWD", "GxCVD", "GxCIMgr", "DefWatch", "ccEvtMgr", "ccSetMgr", "SavRoam", "RTVscan", "QBFCService", "QBIDPService", "Intuit.QuickBooks.FCS", "QBCFMonitorService", "AcrSch2Svc", "AcronisAgent", "CASAD2DWebSvc", "CAARCUpdateSvc"
```

## Terminating Processes

This part of code is also copied and pasted from the **BABUK** source code.

**ROOK** calls **CreateToolhelp32Snapshot** to retrieve a snapshot of all processes and threads in the system. It then calls **Process32FirstW** and **Process32NextW** to enumerate through the snapshot.

For each process whose name is in the list of processes to be terminated, the malware calls **OpenProcess** to retrieve the process's handle and **TerminateProcess** to terminate it.

![alt text](/uploads/rook18.PNG)

*Figure 18: Stopping Target Services.*

Below is the list of processes that are stopped.

``` c
"sql.exe", "oracle.exe", "ocssd.exe", "dbsnmp.exe", "visio.exe", "winword.exe", "wordpad.exe", "notepad.exe", "excel.exe", "onenote.exe", "outlook.exe", "synctime.exe", "agntsvc.exe", "isqlplussvc.exe", "xfssvccon.exe", "mydesktopservice.exe", "ocautoupds.exe", "encsvc.exe", "firefox.exe", "tbirdconfig.exe", "mydesktopqos.exe", "ocomm.exe", "dbeng50.exe", "sqbcoreservice.exe", "infopath.exe", "msaccess.exe", "mspub.exe", "powerpnt.exe", "steam.exe", "thebat.exe", "thunderbird.exe"
```

## Deleting Shadow Copies

This part of code is also copied and pasted from the **BABUK** source code.

**ROOK** first checks if its process is running under a 64-bit processor by calling **IsWow64Process**.

![alt text](/uploads/rook19.PNG)

*Figure 19: Checking Process Architecture.*

If it is, the malware calls **Wow64DisableWow64FsRedirection** to disable file system redirection for its process.

Then it executes **ShellExecuteW** to launch the following command in the command line to delete all shadow copies in the system.

``` powershell
vssadmin.exe delete shadows /all /quiet
```

Finally, if the malware's process is running under a 64-bit architecture, it calls **Wow64RevertWow64FsRedirection** to enable file system redirection.

![alt text](/uploads/rook20.PNG)

*Figure 20: Deleting Shadow Copies.*

## Multithreading Setup

Prior to encrypting files, **ROOK** sets up its own multithreading system.

Initially, it calls **GetSystemInfo** to retrieve the number of processors in the system.

The multithreading structure is divided into two parts: file encryption and directory enumeration.

For file encryption, the malware calculates the maximum number of files to be encrypted by multiple threads at the same time is 24 times the number of processors. It then calls **HeapAlloc** to allocate a global array to store the files that are set to be encrypted and **CreateSemaphoreA** to create 2 semaphores that are used for synchronization among threads that access the file array. Finally, it also calls 
**InitializeCriticalSection** to initialize a critical section that allows one thread to add or remove a file from the global array at a time.

![alt text](/uploads/rook21.PNG)

*Figure 21: Threading Setup for File Encryption.*

For directory enumeration, the malware calculates the maximum number of directories to be enumerated by multiple threads at the same time is 6 times the number of processors. It also creates a global array, 2 semaphores, and a critical section like to the file encryption part above.

![alt text](/uploads/rook22.PNG)

*Figure 22: Threading Setup for Directory Enumeration.*

Next, the malware calls **HeapAlloc** to allocate two arrays to store child thread handles, one for file encryption and the other for directory enumeration. 

**ROOK** then calls **CreateThread** to spawn threads for double the number of processors for each thread array. The functionalities of these threads are later discussed in the [Child Thread](#child-thread) section.

![alt text](/uploads/rook23.PNG)

*Figure 23: Spawning Child Threads.*

## Network Resource Traversal

When the command-line argument **"-paths"** or **"-shares"** is not provided, **ROOK** recursively traverses through all resources in the network.

The malware calls **WNetOpenEnumW** to retrieve an enumeration handle for all network resources and **WNetEnumResourceW** to enumerate through them.

For each network resource, if it's a container for other resources that can also be enumerated, **ROOK** recursively passes it back to the current function to traverse it.

If the resource is just a normal and connectable directory, the malware passes it into a recursive function to traverse it, which will be discussed in the [Drives Traversal](#drives-traversal) section.

![alt text](/uploads/rook24.PNG)

*Figure 24: Traversing Network Resources.*

## Drives Traversal

When the command-line argument **"-paths"** is provided, **ROOK** specifically enumerates them and exits upon completion.

The argument can come in the form of a list of paths, each separated by a comma. Instead of a normal directory path, **ROOK** also accepts a two-character string of a drive letter followed by a colon as a path to a drive.

![alt text](/uploads/rook25.PNG)

*Figure 25: Parsing "-paths" Command-Line Argument.*

When traversing a drive, **ROOK** builds the following drive path.

``` c
\\\\?\\<drive_letter>:
```

With the path, the malware checks and avoids enumerating the drive if it's a CD-ROM drive.

If the drive type is a remote drive, **ROOK** calls **WNetGetConnectionW** to retrieve the remote name of the drive and passes it to be traversed by the **recursive_traverse_dir** function.

If the drive type is not remote drive and CD-ROM drive, the malware simply passes it to the **recursive_traverse_dir** function.

In the **recursive_traverse_dir** function, **ROOK** begins by executing two nested while loop. The first one loops and waits until the **END_ACCESS_DIR_SEMAPHORE** semaphore's count is reduced to zero, and its state is nonsignaled. When this happens, it means every directory in the global directory list is already traversed and no thread is extracting from it.

While waiting for this, the inner while loop waits until the **BEGIN_ACCESS_FILE_SEMAPHORE** semaphore is signaled, which allows the current process to access the global file list. After obtaining the ownership of the critical section for the global file list using **EnterCriticalSection**, **ROOK** extracts the file at the current index, increments the index, and encrypts it. The file encryption routine is later discussed at the [File Encryption](#file-encryption) section.

![alt text](/uploads/rook27.PNG)

*Figure 27: Waiting for Directory List to Be Cleared & Encrypting File in the Meantime.*

Instead of just looping and waiting for the directory list to be cleared, **ROOK** extracts and encrypts files in the global file list during the wait time to increase efficiency and avoids wasting computing resources. This makes the overall enumeration and encryption process quite fast.

Next, the malware calls **EnterCriticalSection** to obtain the ownership of the global directory list and adds the directory path to be traversed in. Then, it calls **ReleaseSemaphore** to release the **BEGIN_ACCESS_DIR_SEMAPHORE** semaphore, which increments its count by one and signals other threads that another directory is available to be enumerated.

![alt text](/uploads/rook28.PNG)

*Figure 28: Adding Directory to Global List & Signaling for Enumeration.*

Then, the function begins enumerating the directory for all its sub-directories. **ROOK** builds the path **"<dir_path>\\\*"** and passes it to **FindFirstFileW** to start the enumeration.

![alt text](/uploads/rook29.PNG)

*Figure 29: Enumerating Directory for Sub-Directories.*

For each sub-directory found, the malware checks if the filename is not in the list of files and directories to avoid. If it's not, the sub-directory full path is constructed and passed back to **recursive_traverse_dir** to be recursively traversed.

Below is the list of files and directories to avoid.

``` c
<log_filename>, "Mozilla Firefox", "$Recycle.Bin", "ProgramData", "All Users", "autorun.inf", "boot.ini", "bootfont.bin", "bootsect.bak", "bootmgr", "bootmgr.efi", "bootmgfw.efi", "desktop.ini", "iconcache.db", "ntldr", "ntuser.dat", "ntuser.dat.log", "ntuser.ini", "thumbs.db", "Program Files", "Program Files (x86)", "AppData", "Boot", "Windows", "Windows.old", "Tor Browser", "Internet Explorer", "Google", "Opera", "Opera Software", "Mozilla", "#recycle", "..", "."
```

![alt text](/uploads/rook30.PNG)

*Figure 30: Recursively Traversing All Sub-Directories.*


If the command-line argument **"-paths"** is not provided, **ROOK** manually mounts all drives that have no volume mounted and traverses through all of them.

First, it builds a list of all drive letters and iterates through it to find drives with type **DRIVE_NO_ROOT_DIR**. Those drives are then added to the end of the list.

![alt text](/uploads/rook31.PNG)

*Figure 31: Finding Drives with an Invalid Root Path.*

Next, **ROOK** calls **FindFirstVolumeW** and **FindNextVolumeW** to scan for available volumes in the system. For each volume, the malware calls **GetVolumePathNamesForVolumeNameW** to retrieve the volume GUID path and **SetVolumeMountPointW** to set the path as the root path for the next no-root drive in the list.

![alt text](/uploads/rook32.PNG)

*Figure 32: Mounting All Unmounted Drives.*

Finally, the malware calls **GetLogicalDrives** to iterate through all the drives in the system and traverse them.

![alt text](/uploads/rook33.PNG)

*Figure 33: Traversing All Mounted Drives.*

## Shares Traversal

When the command-line argument **"-shares"** is provided, **ROOK** specifically enumerates them and exits upon completion.

The argument can come in the form of a list of network server paths, which each separated by a comma. 

![alt text](/uploads/rook34.PNG)

*Figure 34: Parsing "-shares" Command-Line Argument.*

To traverse each share server, the malware calls **NetShareEnum** to retrieve information about each shared resource on it.

For each shared resource, if its type is not a special share reserved for interprocess communication (IPC\$) or remote administration of the server (ADMIN\$), the shared resource is skipped.

If the share name is **"ADMIN$"**, the malware builds the path **"\\\\<server_name>\\ADMIN\$"** and passes it to **recursive_traverse_dir** to be traversed.

![alt text](/uploads/rook35.PNG)

*Figure 35: Traversing Shared Resources.*

## Child Thread

For the spawn child threads, they have two different modes of execution depending on the flag passed in as parameter.

If the flag is 1, the thread will process a directory from the global directory list.

First, it enters a nested while loop like the one we have seen [earlier](#drives-traversal). The first loop waits until the **BEGIN_ACCESS_DIR_SEMAPHORE** semaphore enters a nonsignaled state, which means no thread is adding to the directory list.

While waiting for that, **ROOK** efficiently waits to retrieve access to the global file list, extract a file, and encrypts it similar to the previous nested while loop.

![alt text](/uploads/rook36.PNG)

*Figure 36: Waiting for Global Directory List Access.*

After the directory list is full, the malware obtains ownership of the list's critical section, extracts a directory out, and begins traversing it for sub-files.

![alt text](/uploads/rook37.PNG)

*Figure 37: Extracting Directory & Enumerating for Sub-Files.*

For the enumeration, **ROOK** first builds a path to a ransom note file in the directory, calls **CreateFileW** to create it and **WriteFile** to write the ransom note content to it.

Below is the raw content of the ransom note.

``` css
-----------Welcome. Again. --------------------
[+]Whats Happen?[+]

Your files are encrypted,and currently unavailable. You can check it: all files on you computer has expansion robet.

By the way,everything is possible to recover (restore), but you need to follow our instructions. Otherwise, you cant return your data (NEVER).

[+] What guarantees?[+]

Its just a business. We absolutely do not care about you and your deals, except getting benefits. If we do not do our work and liabilities - nobody will not cooperate with us. Its not in our interests.

To check the file capacity, please send 3 files not larger than 1M to us, and we will prove that we are capable of restoring.

If you will not cooperate with our service - for us, its does not matter. But you will lose your time and data,cause just we have the private key. In practise - time is much more valuable than money.

If we find that a security vendor or law enforcement agency pretends to be you to negotiate with us, we will directly destroy the private key and no longer provide you with decryption services.

You have 3 days to contact us for negotiation. Within 3 days, we will provide a 50% discount. If the discount service is not provided for more than 3 days, the files will be leaked to our onion network. Every more than 3 days will increase the number of leaked files.

Please use the company email to contact us, otherwise we will not reply.

[+] How to get access on website?[+] 

You have two ways:

1) [Recommended] Using a TOR browser!
	a) Download and install TOR browser from this site:hxxps://torproject[.]org/
	b) Open our website:<redacted>[.]onion

2) Our mail box:
	a)<redacted>@onionmail[.]org
	b)<redacted>@onionmail[.]org
	c)If the mailbox fails or is taken over, please open Onion Network to check the new mailbox
------------------------------------------------------------------------------------------------
!!!DANGER!!!
DONT try to change files by yourself, DONT use any third party software for restoring your data or antivirus solutions - its may entail damge of the private key and, as result, The Loss all data.
!!!!!!!

AGAIN: Its in your interests to get your files back. From our side, we (the best specialists) make everything for restoring, please should not interfere.
!!!!!!!

ONE MORE TIME: Security vendors and law enforcement agencies, please be aware that attacks on us will make us even stronger.

!!!!!!!

```

![alt text](/uploads/rook38.PNG)

*Figure 38: Dropping Ransom Note.*

Next, it builds the path **"<dir_path>\\*"** and passes it to **FindFirstFileW** to begin enumerating through files in the directory.

![alt text](/uploads/rook39.PNG)

*Figure 39: Enumerating Files in Directory.*

For each found file, **ROOK** checks to make sure its name is not in the files and directories to avoid list and is not **HowToRestoreYourFiles.txt**.

![alt text](/uploads/rook40.PNG)

*Figure 40: Checking for Invalid Filenames.*

**ROOK** also skips the file if its extension is **".exe"**, **".dll"**, or **".Rook"**. After checking, the malware enters a nested while loop to wait until no thread can add to the global file list and extracts files to encrypt during the wait time.

After getting access to the file list, **ROOK** calls **EnterCriticalSection** to obtain the ownership of the file list's critical section and 
adds the subfile to the list.

![alt text](/uploads/rook41.PNG)

*Figure 41: Adding Subfile to Global File List.*

If the flag from parameter is 1, the child thread will continuously encrypt files from the global directory list until the list is completely empty.

![alt text](/uploads/rook42.PNG)

*Figure 42: Iterating & Encrypting Files in Global List.*

## File Encryption

Prior to file encryption, **ROOK** calls **SetFileAttributesW** to set the file attribute to normal.

It builds the following path **"<file_path>.Rook"** and calls **MoveFileExW** to change the file name to have the encrypted extension **.Rook**.

![alt text](/uploads/rook43.PNG)

*Figure 43: Adding Encrypted Extension.*

Next, the malware calls **CreateFileW** to retrieve the file handle for the target and begins the encryption.

First, it uses the Mbed TLS **CTR_DRBG** context to generates a random 16-byte AES key.

![alt text](/uploads/rook44.PNG)

*Figure 44: Randomly Generating AES Key for File.*

Next, **ROOK** populates the following structures for the file footer.

``` cpp
struct ROOK_FILE_FOOTER
{
  LARGE_INTEGER file_size;
  ROOK_CRYPT_METADATA metadata;
};

struct ROOK_CRYPT_METADATA
{
  _QWORD encrypted_chunk_count;
  _QWORD unk;
  BYTE AES_key_encrypted_by_my_public[256];
  BYTE my_private_key_encrypted_by_Rook_public[2304];
};
```

The malware begins by calling **GetFileSizeEx** to retrieve the size of the file and store it in the file footer. It then uses the victim's RSA public key to encrypt the AES key and store it in the metadata's **AES_key_encrypted_by_my_public** field.

![alt text](/uploads/rook45.PNG)

*Figure 45: Encrypting AES Key Using Victim's Public Key.*

Next, it copies the victim's private key that is encrypted using **ROOK's** public key during [RSA Key Generation](#rsa-key-generation) into the metadata's **my_private_key_encrypted_by_Rook_public** field.

![alt text](/uploads/rook46.PNG)

*Figure 46: Writing Victim's Encrypted Private Key into File Footer.*

If the file size is greater than 0x80000 bytes, the malware reads and encrypts at most three 0x80000-byte chunks at the beginning of the file using AES-128 ECB.

![alt text](/uploads/rook47.PNG)

*Figure 47: Encrypting Files Larger Than 0x80000 Bytes.*

If the file size is less than 0x80000 bytes or is between 0x80000 and 0x180000 bytes, the entire file will be encrypted.

![alt text](/uploads/rook48.PNG)

*Figure 48: Calculating & Encrypting the Last Chunk That Is Less Than 0x80000 Bytes.*

Finally, the file footer is written to the end of the file, which ends the encryption routine.

![alt text](/uploads/rook49.PNG)

*Figure 49: Writing File Footer.*

If **ROOK** is unable to open the file prior to encryption, the malware attempts to terminate the file owner's process.

It first calls **RmStartSession** to starts a new Restart Manager session and **WideCharToMultiByte** to convert the file path to a multibyte buffer.

![alt text](/uploads/rook50.PNG)

*Figure 50: Starting A Restart Manager Session.*

Using that session handle, the malware calls **RmRegisterResources** to register the target file as a resource to the RM.

![alt text](/uploads/rook51.PNG)

*Figure 51: Registering Target File as a Resource.*

Next, it calls **RmGetList** to get a list of all applications that are using the file. For each of these applications, if the application's type is Windows Explorer or a critical process, it is skipped.

Then, **ROOK** checks to make sure the application is not its own ransomware process through the process IDs. Finally, it calls **OpenProcess** to retrieve the process's handle and terminate it using **TerminateProcess**.

![alt text](/uploads/rook52.PNG)

*Figure 52: Terminating File Owners.*

After terminating all processes that are using the file, **ROOK** passes it back in to be encrypted.

![alt text](/uploads/rook53.PNG)

*Figure 53: Setting Up File to Be Encrypted Again.*

## References

https://infosecwriteups.com/alternate-data-streams-ads-54b144a831f1

https://www.sentinelone.com/labs/new-rook-ransomware-feeds-off-the-code-of-babuk/

https://chuongdong.com/reverse%20engineering/2021/01/03/BabukRansomware/

https://chuongdong.com/reverse%20engineering/2021/01/16/BabukRansomware-v3/

