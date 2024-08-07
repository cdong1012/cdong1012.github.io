---
title: BlackMatter Ransomware v2.0
categories:
  - Reverse Engineering
description: Malware Analysis Report - BlackMatter Ransomware v2
---

# BlackMatter Ransomware v2.0

## Contents

- [BlackMatter Ransomware v2.0](#blackmatter-ransomware-v20)
  - [Contents](#contents)
  - [Overview](#overview)
  - [IOCS](#iocs)
  - [Ransom Note](#ransom-note)
- [Static Code Analysis](#static-code-analysis)
  - [Anti-Analysis: Dynamic API Resolving](#anti-analysis-dynamic-api-resolving)
  - [Anti-Analysis: String Encryption](#anti-analysis-string-encryption)
  - [Anti-Analysis: String Comparison](#anti-analysis-string-comparison)
  - [Configuration](#configuration)
  - [Command-line Arguments](#command-line-arguments)
  - [Pre-Encryption Setup](#pre-encryption-setup)
    - [UAC Bypass](#uac-bypass)
    - [Generate Encrypted Extension](#generate-encrypted-extension)
    - [Retrieving Token To Impersonate With Process Injection](#retrieving-token-to-impersonate-with-process-injection)
    - [Parsing Login Credentials](#parsing-login-credentials)
    - [Cryptographic Keys Setup](#cryptographic-keys-setup)
  - [Safe Mode Reboot](#safe-mode-reboot)
    - [Checking Computer Name](#checking-computer-name)
    - [Auto Logon Credential](#auto-logon-credential)
    - [RunOnce Registry Persistence](#runonce-registry-persistence)
    - [Safe Boot Command Execution](#safe-boot-command-execution)
  - [Setting Ransom Wallpaper](#setting-ransom-wallpaper)
    - [Ransom Note Printing](#ransom-note-printing)
  - [Run-Once Mutex](#run-once-mutex)
  - [Wiping Recycle Bins](#wiping-recycle-bins)
  - [Shadow Copies Deletion Through WMI](#shadow-copies-deletion-through-wmi)
  - [Terminating Services through Service Control Manager](#terminating-services-through-service-control-manager)
  - [Terminating Processes](#terminating-processes)
  - [File Encryption](#file-encryption)
    - [Multithreading: Parent Thread](#multithreading-parent-thread)
    - [Multithreading: Parent Thread Communication](#multithreading-parent-thread-communication)
      - [File Owner Termination](#file-owner-termination)
      - [Check If File Is Already Encrypted](#check-if-file-is-already-encrypted)
      - [Checking Large File](#checking-large-file)
      - [Thread Shared Structure](#thread-shared-structure)
    - [Multithreading: Child Threads Encryption](#multithreading-child-threads-encryption)
      - [I. State 0: Reading File](#i-state-0-reading-file)
      - [II. State 1. Encrypt and Write File](#ii-state-1-encrypt-and-write-file)
        - [BlackMatter Custom ChaCha20](#blackmatter-custom-chacha20)
      - [III. State 2. Write File Footer](#iii-state-2-write-file-footer)
      - [IV. State 3. Clean Up](#iv-state-3-clean-up)
      - [Child Thread Communication](#child-thread-communication)
    - [Exchange Mailbox Traversal](#exchange-mailbox-traversal)
    - [Logical Drives Traversal](#logical-drives-traversal)
    - [Network Shares Traversal](#network-shares-traversal)
  - [Network Communication](#network-communication)
  - [Weird Threading Stuff](#weird-threading-stuff)
  - [References](#references)

## Overview

This is my analysis for the **BlackMatter Ransomware** version 2.0.

In this analysis, I only cover **BlackMatter's** ransomware functionalities and leave out details about the anti-analysis and obfuscation stuff. The main reason for this is because I'm just really lazy.

**BlackMatter** uses a hybrid-cryptography scheme of **RSA-1024** and **modified ChaCha20** similar to encrypt files and protect its **ChaCha20** matrix.

Like **Darkside**, its configuration is encrypted and **aPLib-compressed** in memory.

When servers' URLs are provided in the configuration, the malware encrypts informations about the victim's machine and encryption stats using a hard-coded **AES** key and sends them to the remote servers.

Similar to **REvil**, **BlackMatter's** child threads use a shared structure to divide the work into multiple states while encrypting a file.

By basing its multithreading architecture on **REvil's**, **BlackMatter's** encryption is relatively fast.

![alt text](/uploads/blackmatter2.PNG)

*Figure 1: BlackMatter leak site.*

## IOCS

This sample is a 32-bit Windows executable.

**MD5**: 50c4970003a84cab1bf2634631fe39d7

**SHA256**: 520bd9ed608c668810971dbd51184c6a29819674280b018dc4027bc38fc42e57

**Sample**: https://bazaar.abuse.ch/sample/520bd9ed608c668810971dbd51184c6a29819674280b018dc4027bc38fc42e57/

![alt text](/uploads/blackmatter1.PNG)

*Figure 2: BlackMatter victim portal.*

## Ransom Note

The content of the ransom note is encrypted in **BlackMatter's** configuration, and it's dynamically decrypted and written to the ransom note file in every directory.

The ransom note filename is in the form of **<encrypted_file_extension>.README.txt**.

![alt text](/uploads/blackmatter3.PNG)

*Figure 3: BlackMatter ransom note.*

# Static Code Analysis

## Anti-Analysis: Dynamic API Resolving

Since BlackMatter is a combination between LockBit, Darkside, and REvil, it's not suprising that the ransomware obfuscates its API calls from static analysis.

The obfuscation is pretty cool, but I won't analyze it here. I highly suggest fellow analysts to check out how it works if they have time!

![alt text](/uploads/blackmatter4.PNG)

*Figure 3: Dynamic API resolve.*

Check out my IDAPython scripts [dll_exports.py](https://github.com/cdong1012/IDAPython-Malware-Scripts/blob/master/Blackmatter/dll_exports.py) and [revil_api_resolve.py](https://github.com/cdong1012/IDAPython-Malware-Scripts/blob/master/Blackmatter/API_resolve.py) if you want to automate resolving these APIs in **IDA Pro** and speed up your analysis.

These scripts are inspired by the **REVil** scripts from this [OALabs's Youtube video](https://www.youtube.com/watch?v=R4xJou6JsIE).

[Jan G.](https://twitter.com/jan6ru) has a really good blog post explaining the **BlackMatter's** API hashing and obfuscation through trampoline pointers. If you're interested in the technical analysis of this, feel free to check [their work](https://blog.digital-investigations.info/2021-08-05-understanding-blackmatters-api-hashing.html) out.

## Anti-Analysis: String Encryption

Like with other major ransomware out there, most strings in **BlackMatter** are encrypted and resolved during run-time.

The strings that are not encrypted are stored on the stack as stack strings. For each encrypted ones, the encrypted bytes/DWORDs are pushed on the stack and decrypted by XOR-ing with a constant.

This implementation is really similar to that of **Conti** ransomware, and there is probably a good way to automate resolving these with an IDAPython script.

Since I'm lazy during my analysis, I just use **x32dbg** to execute and resolve these stack strings dynamically.

![alt text](/uploads/blackmatter5.PNG)

*Figure 5: Stack string decryption.*

## Anti-Analysis: String Comparison

In ransomware specifically, string comparison is crucial for tasks such as checking the name of processes and services to terminate, files and folders to avoid encrypting, searching for names of DLLs and Windows APIs, etc.

As a result, it helps tremendously if analysts can look at the strings being compared to quickly identify certain functionalities of the ransomware.

**BlackMatter** obfuscates this with a one-way hash function and only compares the strings' hashes instead of the strings themselves. The hash of a string is just the summation of each byte rotated right by 13 with an initial seed.

![alt text](/uploads/blackmatter7.PNG)

*Figure 6: String hashing algorithm.*

The summation makes it impossible to work backward from the hash to produce a string, so resolving these hashes requires heuristic analysis, cracking dictionary, and bruteforcing.

I use and contribute this [tool](https://github.com/sisoma2/malware_analysis/tree/master/blackmatter) by [@sisoma2](https://twitter.com/sisoma2) to look up the hashes that BlackMatter uses! His tool has a great dictionary to crack the hashes, so make sure to use it to aid your analysis!

Below is the list of hashes used by BlackMatter v2 and their strings.

``` rust
0xd3801b00 -> hlp
0x5366e694 -> perflogs
0xe7681bc0 -> rom
0xdd481cc0 -> msi
0xd9c81940 -> key
0xef3a37b3 -> default
0xd57818c0 -> ico
0x67b00e00 -> 386
0xcd2e9b7a -> theme
0x6b66f975 -> intel
0xdd081c00 -> mpa
0xdd101900 -> mdb
0xe9981a00 -> shs
0x267078f5 -> $windows.~bt
0xcd101900 -> edb
0xc6ce6958 -> appdata
0xeb869d00 -> http
0x85aa57e4 -> ntuser.dat.log
0x4a6bb7db -> msstyles
0x4cca7837 -> nomedia
0x49164931 -> accdb
0xc9101840 -> cab
0xe1c018c0 -> ocx
0xdb301900 -> ldf
0x12018c0 -> c$
0xfcc8ab56 -> bootsect.bak
0xdf981b00 -> nls
0xe99018c0 -> scr
0xa6f2d1a7 -> application data
0x4c4b25d4 -> tor browser
0xe7801d00 -> rtp
0xdd201bc0 -> mod
0xf00cae96 -> bootfont.bin
0x846bec00 -> iconcache.db
0xd4aaebb2 -> admin$
0xc7a01840 -> bat
0xc8cef7d1 -> thumbs.db
0xdd301900 -> mdf
0xf1c01c00 -> wpx
0xe1a63bc0 -> boot
0xcbb01c80 -> drv
0xc5481b80 -> ani
0xcbe2aa35 -> ntuser.ini
0x2e75e394 -> programdata
0x4ae29631 -> diagcfg
0xba22623b -> all users
0x4aba94f1 -> diagcab
0xd5c01900 -> idx
0xdd801cc0 -> msp
0xdd181cc0 -> msc
0xeb9f5c34 -> https
0x3907099b -> boot.ini
0x64e29771 -> diagpkg
0x86ccaa15 -> autorun.inf
0xb7e02438 -> svchost.exe
0xe3301c80 -> prf
0xe9601c00 -> spl
0xc5b01900 -> adv
0x452f4997 -> -safe
0xe1881cc0 -> ps1
0xaf16c593 -> themepack
0xe3101900 -> pdb
0xd59818c0 -> ics
0xdb975937 -> ntldr
0xc23aa6f5 -> ntuser.dat
0x3eb272e6 -> explorer.exe
0xb7ea3892 -> msocache
0xe15ed8c0 -> lock
0xcb601b00 -> dll
0xe3426cd7 -> windows
0xc7701a40 -> bin
0xc9601c00 -> cpl
0x5cde3a7b -> public
0xc99eab80 -> icns
0xdf301900 -> ndf
0xd3081d00 -> hta
0x7f07935 -> windows.old
0x45678b17 -> -wall
0xdda81cc0 -> msu
0xe9981e40 -> sys
0x30a212d -> $recycle.bin
0x45471d17 -> -path
0x52cb0b38 -> google
0xdccab8dd -> mozilla
0xc9201b40 -> cmd
0xa1fccbfe -> deskthemepack
0x26687e35 -> $windows.~ws
0xc9901d40 -> cur
0xae018eae -> system volume information
0xdb581b80 -> lnk
0xcd281e00 -> exe
0x82d2a252 -> desktop.ini
0x8cf281cd -> config.msi
0xfe9e7c10 -> runonce.exe
0x36004e4e -> program files
0xd56018c0 -> icl
0xab086595 -> program files (x86)
0xc9681bc0 -> com
```

## Configuration

The configuration of **BlackMatter** samples is encrypted and compressed in memory similar to that of **Darkside**.

During my analysis, I dynamically execute to decrypt it using **x32dbg** and decompress the configuration using **aPLib** in **Python**.

![alt text](/uploads/blackmatter6.PNG)

*Figure 7: BlackMatter config extraction.*

Below is the list of configuration fields that **BlackMatter** supports and their description.

- **RSA_PUBLIC_KEY** (128 bytes): RSA key to encrypt **ChaCha20** Key.
  
- **COMPANY_VICTIM_ID** (16 bytes): Company ID used in data being sent back to remote server to identify victim.

- **AES_KEY** (16 bytes): AES key to encrypt data being sent to remote servers.

- **ENCRYPT_LARGE_FILE_FLAG** (1 byte): Enable chunking to encrypt large files.

- **ATTEMPT_LOGON_FLAG** (1 byte): Enable attempting to log in using user credentials given in the configuration.

- **MOUNT_VOL_AND_ENCRYPT_FLAG** (1 byte): Enable encrypting Exchange mailbox, mounting all volumes, and encrypting them.

- **NETWORK_ENCRYPT_FLAG** (1 byte): Enable retrieving DNS host names and encrypting their network shares

- **TERMINATE_PROCESSES_FLAG** (1 byte): Enable terminating processes specified by the **PROCESSES_TO_KILL** config field.

- **STOP_SERVICES_AND_DELETE_FLAG** (1 byte): Enable stopping and deleting services specified by the **SERVICES_TO_KILL** config field.

- **CREATE_MUTEX_FLAG** (1 byte): Enable creating and checking RunOnce mutex.

- **PRINTER_PRINT_RANSOM_NOTE_FLAG** (1 byte): Enable printing ransom note using the local user's default printer

- **SEND_DATA_TO_SERVER_FLAG** (1 byte): Enable sending victim's info and encrypting stats to remote servers specified by the **REMOTE_SERVER_URLS** config field.

- **FOLDER_HASHES_TO_AVOID**: **Base64**-encoded list of 4-byte hashes of folder names to avoid encrypting.

- **FILE_HASHES_TO_AVOID**: **Base64**-encoded list of 4-byte hashes of filenames to avoid encrypting.

- **EXTENSION_HASHES_TO_AVOID**: **Base64**-encoded list of 4-byte hashes of extensions to avoid encrypting.

- **COMPUTERNAMES_TO_AVOID**: **Base64**-encoded list of computer names to avoid encrypting (not used in this sample).

- **PROCESSES_TO_KILL**: **Base64**-encoded list of processe to kill.

- **SERVICES_TO_KILL**: **Base64**-encoded list of services to kill.

- **REMOTE_SERVER_URLS**: **Base64**-encoded list of remote servers to contact.

- **LOGIN_CREDENTIALS**: List of credentials to try logging into the machine (not used in this sample).

- **RANSOM_NOTE_CONTENT**: **Base64**-encoded and encrypted content of the ransom note.

- **RANSOM_NOTE_CONTENT_HASH**: Checksum of ransom note content.

Here is the configuration of this v2 sample in JSON form. I generate this using this [auto config extracting tool](https://github.com/advanced-threat-research/DarkSide-Config-Extract) and fix up the configuration field names according to my analysis. Huge shoutout to the guys at **McAfee Advanced Threat Research** for this!

``` JSON
{
  "RSA_PUBLIC_KEY":  "4FDB27F0D5F8A0741EBE1A8C08E5B98ABECE2C281166A7FFDCF239A8A77FD2A4FC6B8828A5F3F9F5FA4B245CC90386953D6469368DAD281CA1D688F2556725D9422D08E1191230999B2E54E4103B1C19199C96E350C216B39B3D2ADDB315A4284A9A3C8C5058924AED366DD030FD4E211178BCDC4C79406B75C87EDC1851676A",
  "COMPANY_VICTIM_ID":  "24483508BCCFE72E63B26A1233058170",
  "AES_KEY":  "196387BAD88422E3F08474FA8F7E796E",
  "ENCRYPT_LARGE_FILE_FLAG":  "false",
  "ATTEMPT_LOGON_FLAG":  "false",
  "MOUNT_VOL_AND_ENCRYPT_FLAG":  "true",
  "NETWORK_ENCRYPT_FLAG": "true",
  "TERMINATE_PROCESSES_FLAG":  "true",
  "STOP_SERVICES_AND_DELETE_FLAG": "true",
  "CREATE_MUTEX_FLAG": "true",
  "SEND_DATA_TO_SERVER_FLAG": "true",
  "PRINTER_PRINT_RANSOM_NOTE_FLAG":  "true",
  "PROCESSES_TO_KILL":  [{
      "": "encsvc"
    }, {
      "": "thebat"
    }, {
      "": "mydesktopqos"
    }, {
      "": "xfssvccon"
    }, {
      "": "firefox"
    }, {
      "": "infopath"
    }, {
      "": "winword"
    }, {
      "": "steam"
    }, {
      "": "synctime"
    }, {
      "": "notepad"
    }, {
      "": "ocomm"
    }, {
      "": "onenote"
    }, {
      "": "mspub"
    }, {
      "": "thunderbird"
    }, {
      "": "agntsvc"
    }, {
      "": "sql"
    }, {
      "": "excel"
    }, {
      "": "powerpnt"
    }, {
      "": "outlook"
    }, {
      "": "wordpad"
    }, {
      "": "dbeng50"
    }, {
      "": "isqlplussvc"
    }, {
      "": "sqbcoreservice"
    }, {
      "": "oracle"
    }, {
      "": "ocautoupds"
    }, {
      "": "dbsnmp"
    }, {
      "": "msaccess"
    }, {
      "": "tbirdconfig"
    }, {
      "": "ocssd"
    }, {
      "": "mydesktopservice"
    }, {
      "": "visio"
    }],
  "SERVICES_TO_KILL": [{
      "": "mepocs"
    }, {
      "": "memtas"
    }, {
      "": "veeam"
    }, {
      "": "svc$"
    }, {
      "": "backup"
    }, {
      "": "sql"
    }, {
      "": "vss"
    }, {
      "": "msexchange"
    }],
  "REMOTE_SERVER_URLS":  [{
      "": "hxxps://mojobiden[.]com"
    }, {
      "": "hxxp://mojobiden[.]com"
    }],
  "RANSOM_NOTE_CONTENT":  [{
      "": "      ~+                                       
                     *       +
               '     BLACK        |
           ()    .-.,='``'=.    - o -         
                 '=/_       \\     |           
              *   |  '=._    |                
                   \\     `=./`,        '    
                .   '=.__.=' `='      *
       +             Matter        +
            O      *        '       .
      
      >>> What happens?
         Your network is encrypted, and currently not operational. 
         We need only money, after payment we will give you a decryptor for the entire network and you will restore all the data.
      
      >>> What guarantees? 
         We are not a politically motivated group and we do not need anything other than your money. 
         If you pay, we will provide you the programs for decryption and we will delete your data. 
         If we do not give you decrypters or we do not delete your data, no one will pay us in the future, this does not comply with our goals. 
         We always keep our promises.
      
      >>> How to contact with us? 
         1. Download and install TOR Browser (hxxps://www[.]torproject[.]org/).
         2. Open hxxp://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/<REDACTED>
        
      >>> Warning! Recovery recommendations.  
         We strongly recommend you to do not MODIFY or REPAIR your files, that will damage them."
    }],
    "RANSOM_NOTE_CONTENT_HASH": "38E73655"
}
```

## Command-line Arguments

**BlackMatter** can run with or without command-line arguments.

Below is the list of arguments that can be supplied by the operator.

| Argument   | Description |
| -------- | ----------- |
| **-path \<target\>** | Path to a directory to be encrypted specifically |
| **\<target\>** |  Path to a directory to be encrypted specifically |
| **-safe** | Enable safe mode reboot |
| **-wall** |  Sets up wallpaper and print ransom note  |

## Pre-Encryption Setup

### UAC Bypass

During setup, **BlackMatter** checks if it currently runs with Admin credentials.

First, it calls **SHTestTokenMembership** to check if its process's token is a member of the administrators' group in the built-in domain.

![alt text](/uploads/blackmatter8.PNG)

*Figure 8: Checking token membership.*

Next, after querying the system's OS version from the **PEB**, the ransomware checks if the current OS is **Windows 7** and above.

![alt text](/uploads/blackmatter9.PNG)

*Figure 9: Checking OS version.*

Finally, it checks the current process's token belongs to the built-in system domain groups used for administration.

![alt text](/uploads/blackmatter10.PNG)

*Figure 10: Checking token authority.*

If the checks pass and the process has admin privilege, the malware does not attempt UAC bypass.

For UAC bypass, using **LdrEnumerateLoadedModules**, it registers **"dllhost.exe"** in System32 as the **ImagePathName** and **CommandLine** field in the **ProcessParameters** field of the process's **PEB**. This initial setup allows it to host and execute COM Objects as **"dllhost.exe"**.

![alt text](/uploads/blackmatter11.PNG)

*Figure 11: Setup execution as dllhost.exe.*

**BlackMatter** then calls **CoGetObject** with the object name below to retrieve the COM interface **ICMLuaUtil**, which is commonly used for UAC bypass.

``` r
  Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}
```

The malware then executes the **ShellExec** function from the **ICMLuaUtil** interface to relaunch itself with its original command-line arguments, which elevates the new process to a higher privilege.

![alt text](/uploads/blackmatter12.PNG)

*Figure 12: UAC bypass and relaunch.*

Finally, it terminates itself by calling **NtTerminateProcess**.

### Generate Encrypted Extension

The encrypted extension is dynamically generated using the victim's machine GUID, which makes it unique on every system.

First, **BlackMatter** queries the value of the registry key below to get the machine GUID.

``` r
  HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
```

Next, the malware puts the machine GUID through 3 rounds of hashing, byte swaps, and **Base64**-encode the final hash to generate the encrypted extension.

Because the ASCII characters **'+', '/', and '='** in a **Base64** string does not work really well in a file extension, **BlackMatter** replaces **'+'** with **'x'**, **'/'** with **'i'**, and  **'='** with **'z'**.

![alt text](/uploads/blackmatter13.PNG)

*Figure 13: Generating encrypted file extension.*

The malware reuses this file extension as the ransom note name by appending it in front of **".README.txt"**.

![alt text](/uploads/blackmatter14.PNG)

*Figure 14: Generating ransom note filename.*

### Retrieving Token To Impersonate With Process Injection

**BlackMatter** attempts to retrieve and duplicate the token of an elevated process running on the system. The malware later launches threads and has them impersonate the target process using this token.

First, it checks if the current process's user is **LocalSystem**, a special account used by the operating system. Then, it calls **NtQueryInformationToken** to query the token user information and checks if the first sub authority of the process's SID is **SECURITY_LOCAL_SYSTEM_RID**.

![alt text](/uploads/blackmatter15.PNG)

*Figure 15: Checking for LocalSystem.*

If the process is running as **LocalSystem**, **BlackMatter** uses the current user's token as its elevated token.

If not, the malware calls **NtQuerySystemInformation** to query information about processes on the system. For each process entry, it checks if the process's name is **explorer.exe** and retrieves its unique process ID.

![alt text](/uploads/blackmatter16.PNG)

*Figure 16: Retrieving Explorer's process ID.*

Next, it calls **NtOpenProcess** with the process ID to get the process's handle and retrieves the process's token with **NtOpenProcessToken**.

Finally, **BlackMatter** calls **NtDuplicateToken** to duplicate the **Explorer's** token.

If this fails but the current process's token is a member of the administrators' group in the built-in domain, **BlackMatter** pulls some process injection shenaningans to retrieve a token of a **svchost.exe** process.

First, it uses the same trick in **Figure 16** to retrieve the process ID and handle of a **svchost.exe** process.

![alt text](/uploads/blackmatter17.PNG)

*Figure 17: Retrieving svchost.exe process ID and handle.*

Next, it checks if the **svchost.exe** process is running as a 64-bit process.

If it is 64-bit, the malware decrypts two different shellcodes in memory. The raw shellcodes can be found [here](https://github.com/cdong1012/IDAPython-Malware-Scripts/blob/master/Blackmatter/blackmattershellcode.7z).

After allocating memory in the **svchost.exe** process using **NtAllocateVirtualMemory**, **BlackMatter** writes the first shellcode into the memory region of the second shellcode before setting up and executing the second shellcode.

![alt text](/uploads/blackmatter18.PNG)

*Figure 18: Injecting 64-bit shellcodes into Svchost.*

After being injected, the second shellcode allocates virtual memory in the **svchost** process using **NtAllocateVirtualMemory**, writes the first shellcode in using **NtWriteVirtualMemory**, and create a new thread to execute the first shellcode using **NtCreateThreadEx**.

![alt text](/uploads/blackmatter19.PNG)

*Figure 19: Second shellcode launching first shellcode As Svchost.*

The first shellcode calls **WTSQueryUserToken** to obtain the primary access token of the logged-on user and calls **NtDuplicateObject** to duplicate that token. This token is passed back into the main ransomware thread.

![alt text](/uploads/blackmatter20.PNG)

*Figure 20: First shellcode retrieving the primary access token of the logged-on user.*

If the **svchost** process is running as a 32-bit process instead, the malware decrypts the third shellcode and manually creates a remote thread using **CreateRemoteThread** to launch it. This shellcode is basically just the 32-bit version of the first shellcode.

![alt text](/uploads/blackmatter21.PNG)

*Figure 20: Launching the third shellcode.*

### Parsing Login Credentials

If the **ATTEMPT_LOGON_FLAG** is true and **LOGIN_CREDENTIALS** are provided in the configuration, the malware parses those credential data before attempting authentication.

The **LOGIN_CREDENTIALS** field is a **Base64**-encoded and encrypted buffer of strings, and each credential string is in the form below.

``` rust
<username>@<domain>:password
```

Since this v2 sample doesn't have this field in its configuration, I just base the analysis on its code and others' reports for **BlackMatter v1**.

After decoding and decrypting the credentials, the malware iterates through each credential's username and password and calls **LogonUserW** to log in the local machine.

If the logging in is successful, **BlackMatter** allocates heap buffers and stores the valid credential's username, password, and domain name in there for later usage.

![alt text](/uploads/blackmatter22.PNG)

*Figure 22: Parsing credentials.*

Next, it calls **NtQueryInformationToken** to query the authentication token's group information and checks if the token belongs to the **DOMAIN_ADMINS** group.

![alt text](/uploads/blackmatter23.PNG)

*Figure 23: Check if account is in domain admins.*

If the token belongs to the **DOMAIN_ADMINS** group, the malware calls **SHTestTokenMembership** to check if the token has **DOMAIN_ALIAS_RID_ADMINS** privilege.

If it does not have enough privilege, **BlackMatter** frees all the heap buffers storing the credential and does not user it later.

![alt text](/uploads/blackmatter24.PNG)

*Figure 24: Skip if credential doesn't have proper privilege.*

### Cryptographic Keys Setup

**BlackMatter** has multiple key buffers to use depending on the size of the file being encrypted.

Below is the layout of these buffers.

``` c
struct KeyBuffer {
  DWORD RSA_encrypted_ChaCha20_matrix_Checksum;
  BYTE RSA_encrypted_ChaCha20_matrix[128];
  BYTE ChaCha20_Matrix[124];
}
```

To populate each of these, **BlackMatter** first randomly generates the **ChaCha20** matrix.

![alt text](/uploads/blackmatter25.PNG)

*Figure 25: ChaCha20 matrix generation.*

For **BlackMatter v2**, the matrix is 124-byte or 31-DWORD in length. The first 29 DWORDs in the buffer is randomly generated using assembly instructions **cpuid, rdrand, rdseed, and __rdtsc**. The 30th DWORD is the first 4 bytes in the **RSA** Public Key from the configuration, and the last DWORD contains 3 randomly generated bytes.

The raw matrix is copied to the last 124 bytes of the **RSA_encrypted_ChaCha20_matrix** buffer, and BlackMatter puts the encryption skipped size in the first DWORD of this buffer (0 if chunking is not enabled).

This buffer is then encrypted by the **RSA** public key from the configuration, and the malware generates and writes the encrypted result to the **RSA_encrypted_ChaCha20_matrix** field. It also generates the checksum of this encrypted buffer and writes it in the **RSA_encrypted_ChaCha20_matrix_Checksum** field.

![alt text](/uploads/blackmatter26.PNG)

*Figure 26: Key buffer generation.*

**BlackMatter** randomly generates 11 different key buffers that are used depending on the size of the file to be encrypted.

Below is the list of skipped sizes **BlackMatter** uses.
  
- 0x0
- 0x200000
- 0x400000
- 0x800000
- 0x1000000
- 0x2000000
- 0x4000000
- 0x8000000
- 0x10000000
- 0x20000000
- 0x40000000

![alt text](/uploads/blackmatter61.PNG)

*Figure 27: Key buffer generation 2.*

## Safe Mode Reboot

If the command-line argument **-safe** is provided and the process's token belongs to **DOMAIN_ALIAS_RID_ADMINS**, **BlackMatter** attempts to force the system to reboot into safe mode in order to gain more privilege to execute itself.

### Checking Computer Name

The malware gets the computer name with **GetComputerNameW** and compares its hash with the list of hashes from the **COMPUTERNAMES_TO_AVOID** field in the configuration. If the hash is in the list, **BlackMatter** skips this operation.

![alt text](/uploads/blackmatter27.PNG)

*Figure 28: Checking computer name.*

### Auto Logon Credential

Prior to activating safe mode, **BlackMatter** retrieves proper user credentials to modify the **Winlogon** registry key.

First, if **ATTEMPT_LOGON_FLAG** is true and the username, password, and domain name are properly parsed from the configuration, then the malware just uses those credentials.

If not, it calls **NetUserEnum** with a filter for normal accounts. **BlackMatter** iterates through user information entries until it finds one with the user ID of 500, which is the ID for normal users. If the account corresponding to this entry is disabled, the malware enables it manually by setting the flags in the user information entry.

![alt text](/uploads/blackmatter28.PNG)

*Figure 29: Enumerating for normal user account.*

Next, **BlackMatter** generates a new password for this account. The format of the password string is 3 random uppercase letters, 1 random character of **'#'** or **'&'**, 3 random numbers, 1 random character of **'#'** or **'&'**, and 4 random lowercase letters.

The malware updates the user account entry with this new password and calls **NetUserSetInfo** to udate the user account with the updated entry.

![alt text](/uploads/blackmatter29.PNG)

*Figure 30: Generating new password and updating account.*

Next, **BlackMatter** sets the following registry keys to these values.

``` rust
- SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon: "1"
- SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultUserName: Account username
- SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultDomainName: Account domain name
- SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultPassword: Account password
```

This sets the default credentials to the account that **BlackMatter** has control over (with the password from configuration or the newly generated password) and enables automatic admin logon upon reboot.

It also calls **LsaStorePrivateData** to store and protect the account's password locally.

![alt text](/uploads/blackmatter30.PNG)

*Figure 31: Setting logon credentials and enabling auto admin logon.*

### RunOnce Registry Persistence

**BlackMatter** sets the value of the registry key **SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce** to its own executable path to automatically launch itself upon reboot in safe mode.

The registry key name is randomly generated in the format of 3 random uppercase letters, 3 random numbers, and 3 random lowercase letters.

![alt text](/uploads/blackmatter31.PNG)

*Figure 32: Persistence through registry.*

### Safe Boot Command Execution

Prior to executing commands to enable safe boot, **BlackMatter** sets up wallpaper operations that are documented [here](#setting-ransom-wallpaper) without calling **SystemParametersInfoW** to change the wallpaper.

If the enable flag being passed as a parameter is true, **BlackMatter** executes one of these commands with **WinExec** based on the OS version to enable safe mode reboot.

``` rust
- Below Windows Vista: bootcfg /raw /a /safeboot:network /id 1
- Windows Vista and above: bcdedit /set {current} safeboot network
```

If the enable flag being passed as a parameter is false, **BlackMatter** executes one of these commands with **WinExec** based on the OS version to disable safe mode reboot.

``` rust
- Below Windows Vista: bootcfg /raw /fastdetect /id 1
- Windows Vista and above: bcdedit /deletevalue {current} safeboot
```

Finally, it calls **NtShutdownSystem** to reboot the system.

![alt text](/uploads/blackmatter32.PNG)

*Figure 33: Configuring system to boot into Safe Mode.*

## Setting Ransom Wallpaper

If the command-line argument **-wall** is provided, **BlackMatter** generates a Bitmap file and sets it as the wallpaper on the victim's computer.

First, using **NtQuerySystemInformation**, it queries all processes' information on the system and terminates all **Run Once Wrapper Utility** processes with the image name **runonce.exe** using **NtTerminateProcess**.

![alt text](/uploads/blackmatter33.PNG)

*Figure 34: Terminating runonce.exe.*

Next, the malware calls **GetShellWindow**(if the OS is Windows Vista or above) or **GetDesktopWindow** to retrieve a handle to the desktop window. It continues to do this until it gets a valid handle and the window is currently visible.

![alt text](/uploads/blackmatter34.PNG)

*Figure 35: Retrieving desktop window.*

Finally, **BlackMatter** sets up the wallpaper to display the ransom instruction.

The malware sets the following registry keys.

``` rust
- HKLM\SOFTWARE\<ENCRYPTED_EXTENSION>\hScreen: Window screen height
- HKLM\SOFTWARE\<ENCRYPTED_EXTENSION>\wScreen: Window screen width
```

![alt text](/uploads/blackmatter35.PNG)

*Figure 36: Setting window screen registry Keys.*

Next, it creates a handle to the **Times New Roman** font and writes the ransom instruction using the font into a Bitmap.

The content of the ransom instruction is documented below.

``` c
BlackMatter Ransomware encrypted all your files!
To get your data back and keep your privacy safe,
you must find <Ransom note filenam> file
and follow the instructions!
```

![alt text](/uploads/blackmatter36.PNG)

*Figure 37: Generating ransom wallpaper.*

After creating the Bitmap in memory, the malware writes it to disk at the path below.

``` rust
<special folder path>/<encrypted extension>.bmp
```

![alt text](/uploads/blackmatter37.PNG)

*Figure 38: Writing bitmap content to disk.*

Using the elevated token it has, **BlackMatter** retrieves the token's process's SID and create the following registry key.

``` rust
- HKU\<Process SID>\Control Panel\Desktop
```

It sets the following registry key.

``` rust
- HKU\<Process SID>\Control Panel\Desktop\WallPaper: Bitmap file path
- HKU\<Process SID>\Control Panel\Desktop\WallpaperStyle: "10"
```

To set the victim's machine's wallpaper to the generated Bitmap, **BlackMatter** calls **SystemParametersInfoW** to set **SPI_SETDESKWALLPAPER** to the Bitmap disk path if the enable flag from the function's parameter is true.

![alt text](/uploads/blackmatter38.PNG)

*Figure 39: Setting ransom wallpaper.*

### Ransom Note Printing

When the command-line argument **-wall** is provided, **BlackMatter** also prints the ransom note using the system's default printer.

If the **PRINTER_PRINT_RANSOMNOTE_FLAG** in the configuration is 1, the malware retrieves the current directory of the ransomware executable with **GetCurrentDirectoryW** and drops a ransom note file in there.

![alt text](/uploads/blackmatter39.PNG)

*Figure 40: Function to drop ransom note file.*

Then, it calls **GetDefaultPrinterW** to retrieve the system's default printer and calls **ShellExecuteW** to execute the **print** command to print the ransom note.

![alt text](/uploads/blackmatter92.PNG)

*Figure 41: Function to print ransom note file.*

## Run-Once Mutex

If the **CREATE_MUTEX_FLAG** in the configuration is 1, the malware checks if there is another instance of itself running by checking if the mutex below already exists using **CreateMutex**.

``` rust
- Global\<MD4 hash of machine GUID>
```

![alt text](/uploads/blackmatter40.PNG)

*Figure 42: Generating mutex name.*

If there is another instance, the malware returns immediately and does not encrypt anything.

![alt text](/uploads/blackmatter41.PNG)

*Figure 43: Existing when mutex can't be opened.*

If there is no other instance running, **BlackMatter** keeps the mutex opened until it finishes encrypting to prevent any other instance of itself from running.

## Wiping Recycle Bins

Prior to file encryption, **BlackMatter** wipes the recycle bin folder of every drive on the system.

For each drive, the malware manually iterates through folders in the first layer of the drive and stops when it finds the first folder with **"recycle"** in the name.

![alt text](/uploads/blackmatter42.PNG)

*Figure 44: Finding Recycle Bin in drives.*

Afterward, it uses **FindFirstFileEx** and **FindNextFileW** to iterate through the Recycle Bin folder and looks for all folders that begins with **"S-"**. Once found, the folders and their contents are recursively deleted using **DeleteFileW**.

![alt text](/uploads/blackmatter43.PNG)

*Figure 45: Wiping Recycle Bin.*

This function to wipe Recycle Bin is called on every fixed and removable logical drives on the system.

![alt text](/uploads/blackmatter44.PNG)

*Figure 46: Wiping all Recycle Bins.*

## Shadow Copies Deletion Through WMI

The malware calls **CoCreateInstance** to create an **IWbemLocator** object using the IID *{DC12A687-737F-11CF-884D-00AA004B2E24}* and CLSID *{CB8555CC-9128-11D1-AD9B-00C04FD8FDFF}*.

It then calls **CoCreateInstance** to create an **IWbemContext** object using the CLSID *{674B6698-EE92-11D0-AD71-00C04FD8FDFF}*.

If the system architecture is **x64**, it calls the **IWbemContext::SetValue** function to set the value of **"__ProviderArchitecture"** to **64**.

**BlackMatter** calls the **IWbemLocator::ConnectServer** method to connect with the local **ROOT\CIMV2** namespace and obtain the pointer to an **IWbemServices** object.

![alt text](/uploads/blackmatter45.PNG)

*Figure 47: Connecting to ROOT\CIMV2 for IWbemServices Object.*

Next, it calls **IWbemServices::ExecQuery** to execute the WQL query below to get the **IEnumWbemClassObject** object for querying shadow copies.

``` SQL
SELECT * FROM Win32_ShadowCopy
```

The malware calls **IEnumWbemClassObject::Next** to enumerate through all shadow copies on the system, **IEnumWbemClassObject::Get** to get the ID of each shadow copies, and **IWbemServices::DeleteInstance** to delete them.

![alt text](/uploads/blackmatter46.PNG)

*Figure 48: Deleting shadow copies through WMI.*

## Terminating Services through Service Control Manager

If the **STOP_SERVICES_AND_DELETE_FLAG** field is set to true in the configuration, **BlackMatter** terminates and deletes all services whose name's hash is in the **SERVICES_TO_KILL** list in the configuration.

First, the malware calls **OpenSCManagerW** to get a service control manager handle for active services.

It then calls **EnumServicesStatusExW** to enumerate the name of all **Win32** services. If the hash of the service name is in the list, the malware terminates it by calling **ControlService** to send the **SERVICE_CONTROL_STOP** control code to the service handle.

Then, it calls **DeleteService** to completely delete the service.

![alt text](/uploads/blackmatter47.PNG)

*Figure 49: Enumerating and deleting services.*

## Terminating Processes

If the **TERMINATE_PROCESSES_FLAG** field is set to true in the configuration, **BlackMatter** terminates all processes whose name's hash is in the **PROCESSES_TO_KILL** list in the configuration.

The malware calls **NtQuerySystemInformation** to query and enumerate through all system's processes.

If the hash of the process's name is in the list, **BlackMatter** terminates it by calling **NtOpenProcess** using the process's ID to retrieve the process handle and **NtTerminateProcess** to terminate it.

![alt text](/uploads/blackmatter48.PNG)

*Figure 50: Terminating target processes.*

## File Encryption

Like **REvil** and **Darkside**, **BlackMatter** uses multithreading with I/O completion port to communicate between a parent thread- (check and send files) and the child threads (encrypt files) to speed up encryption.

### Multithreading: Parent Thread

In **BlackMatter** multithreading setup, the parent thread is spawned after the child threads.

This parent thread function receives a parameter of a file/directory path. It first checks if this path is a directory or not.

If the path is a directory, the malware escalates the parent thread's base priority level to **THREAD_PRIORITY_HIGHEST**.

Next, it allocates memory for an array to store sub-directories inside of the target directory to encrypt.

![alt text](/uploads/blackmatter49.PNG)

*Figure 51: Parent thread: Processing directory.*

The parent thread proceeds to drop a ransom note in the target directory and begins enumerating through the directory using **FindFirstFileExW** and **FindNextFileW**.

It avoids all files and sub-directories with names **"."** and **"."** and with the attributes **FILE_ATTRIBUTE_REPARSE_POINT** and **FILE_ATTRIBUTE_SYSTEM**.

![alt text](/uploads/blackmatter50.PNG)

*Figure 52: Parent thread: Processing sub-files and sub-directories.*

If **BlackMatter** finds a sub-directory, it checks if the hash of the name of the directory is in the **FOLDER_HASHES_TO_AVOID** list or if the name is **"windows**.

![alt text](/uploads/blackmatter52.PNG)

*Figure 53: Parent thread: Checking directory names.*

Below is the list of folder names whose hash is in **FOLDER_HASHES_TO_AVOID**.

``` text
system volume information
intel
$windows.~ws
application data
$recycle.bin
mozilla
program files (x86)
program files
$windows.~bt
public
msocache
windows
default
all users
tor browser
programdata
boot
config.msi
google
perflogs
appdata
windows.old
```

If the sub-directory is valid to encrypt, **BlackMatter** adds it to the back of the directory array.

After finish enumerating the target directory, **BlackMatter** walks through the directory array and enumerates the directories listed in there. This allows multilayered traversal through directories without using recursion, which significantly improves performance by eliminating the stack overhead from recursive calls.

![alt text](/uploads/blackmatter53.PNG)

*Figure 54: Parent Thread: Multilayered directory traversal.*

If it finds a file, the filename is checked against the **FILE_HASHES_TO_AVOID** list and the file extension is checked against the **EXTENSION_HASHES_TO_AVOID** list.

![alt text](/uploads/blackmatter51.PNG)

*Figure 55: Parent Thread: Checking filenames and extensions.*

Below is the list of filenames whose hash is in the **FILE_HASHES_TO_AVOID** list.

``` text
desktop.ini
autorun.inf
ntldr
bootsect.bak
thumbs.db
boot.ini
ntuser.dat
iconcache.db
bootfont.bin
ntuser.ini
ntuser.dat.log
```

Below is the list of extensions whose hash is in the **EXTENSION_HASHES_TO_AVOID** list.

``` text
themepack
nls
diagpkg
msi
lnk
exe
cab
scr
bat
drv
rtp
msp
prf
msc
ico
key
ocx
diagcab
diagcfg
pdb
wpx
hlp
icns
rom
dll
msstyles
mod
ps1
ics
hta
bin
cmd
ani
386
lock
cur
idx
sys
com
deskthemepack
shs
ldf
theme
mpa
nomedia
spl
cpl
adv
icl
msu
```

If the file passes these checks, the parent thread will send it to the child threads to be encrypted.

If the file is a link with **.lnk** extension, **BlackMatter** manually resolves the link to get the full path to the file before encrypting it.

First, using the LinkCLSID of **{00021401-0000-0000-C000-000000000046}** and the **IShellLinkW** RIID of **{000214F9-0000-0000-C000-000000000046}**, the malware retrieves an **IShellLinkW** interface.

Using the **QueryInterface** function of the **IShellLinkW** interface with the **IPersistFile** RIID {0000010b-0000-0000-C000-000000000046}, the malware retrieves the **IPersistFile** interface.

It calls the **IPersistFile->Load** function to load the link file to read.

After loading, **BlackMatter** calls **IShellLinkW->GetPath** to retrieves the full file path from the link.

![alt text](/uploads/blackmatter90.PNG)

*Figure 56: Resolving full path from link.*

### Multithreading: Parent Thread Communication

#### File Owner Termination

Before sending a file to child threads to be encrypted, the parent thread terminates all processes/services that are currently accessing the file using the Windows Restart Manager.

**BlackMatter** first calls **RmStartSession** to start a new Restart Manager session, **RmRegisterResources** to register the target file with the Restart Manager as a resource, and **RmGetList** to get a list of all applications and services that are currently using it.

![alt text](/uploads/blackmatter54.PNG)

*Figure 57: Parent thread: Registering file with Restart Manager.*

It iterates through the list of processes and services and terminates all whose application type is not **RmCritical** and **RmExplorer**

![alt text](/uploads/blackmatter55.PNG)

*Figure 58: Parent thread: Iterating and terminating file owners.*

To terminate a service, **BlackMatter** calls **OpenSCManagerW** to establishes a connection to the service control manager, **OpenServiceW** to obtain a handle to the target service, **ControlService** to send the control stop code to the service to stop it, and **DeleteService** to delete it.

![alt text](/uploads/blackmatter56.PNG)

*Figure 59: Service deletion.*

To terminate a process, **BlackMatter** calls **NtOpenProcess** to obtain a handle to the target process and **NtTerminateProcess** to terminate it.

![alt text](/uploads/blackmatter57.PNG)

*Figure 60: Process termination.*

#### Check If File Is Already Encrypted

At the end of the encryption, the **RSA_encrypted_ChaCha20_matrix_Checksum** and **RSA_encrypted_ChaCha20_matrix** fields in the **KeyBuffer** structure from [Cryptographic Keys Setup](#cryptographic-keys-setup) are appended to the file footer.

When **BlackMatter** needs to check if a file is encrypted, it extracts the memory buffer where the **RSA_encrypted_ChaCha20_matrix** field is supposed to be, generates its checksum, and compares it to the value at where the **RSA_encrypted_ChaCha20_matrix_Checksum** field is supposed to be.

![alt text](/uploads/blackmatter58.PNG)

*Figure 61: Check if file is already encrypted.*

#### Checking Large File

A feature to process large files is added to **BlackMatter v2.0**.

When the **ENCRYPT_LARGE_FILE_FLAG** is true in the configuration, the malware checks if the file is a large file through its extension.

If the file's extension is in the list below, then the file is classified as large.

```
mdf
ndf
edb
mdb
accdb
```

The lengths of these are quite short and predictable, so I just bruteforce them with a Python script.

![alt text](/uploads/blackmatter59.PNG)

*Figure 62: Check if file is large.*

#### Thread Shared Structure

Prior to populating the shared structure between parent and child threads, the malware appends the encrypted extension to the file path and calls **MoveFileExW** to move the original file's content to this new filename.

In the case where the new filename already exists, the malware manually adds **-[number]** to the filename before the extension where **number** is incremented from 0 until the filename does not exist in the folder.

![alt text](/uploads/blackmatter60.PNG)

*Figure 63: Create file with encrypted extension.*

The shared structure is used by threads to communicate with each other.

Below is my rough recreation of this structure based on the offset of the fields.

``` c
struct BlackmatterFileStruct
{
  LONGLONG errorCode;
  DWORD originalfilePointerLow;
  DWORD originalfilePointerHigh;
  int padding;
  DWORD filePointerLow;
  DWORD filePointerHigh;
  DWORD skippedBytesLow;
  DWORD skippedBytesHigh;
  HANDLE fileHandle;
  DWORD threadCurrentState;
  BYTE rawChaCha20Matrix[124];
  DWORD fileSize;
  BYTE padding2[368];
  BYTE fileFooter[132];
  DWORD *bytesToRead;
  BYTE *bufferToReadData;
};
```

First, the parent thread checks the file size to populate the **bytesToRead** field. If the file size is 0x100000 bytes or more, the **bytesToRead** value is maxed out at **0x100000**. This means file data is read and encrypted in 0x100000-byte chunks.

![alt text](/uploads/blackmatter62.PNG)

*Figure 64: Setting encrypting size.*

**BlackMatter** then populates the **rawChaCha20Matrix** and **fileFooter** field with the buffers generated in [Cryptographic Keys Setup](#cryptographic-keys-setup).

Each of these buffers is dedicated to a specific skipped size between chunks.

Below is the conversion between the file size the skipped size between chunks.

| File Type   | File Size | Skipped Size |
| -------- | ----------- | ----------- |
| Small | Any size | 0 byte |
| Large | Less than 0x8000000 bytes | 0x200000 bytes|
| Large | Between 0x8000000 and 0x20000000 - 1 bytes | 0x400000 bytes |
| Large | Between 0x20000000 and 0x80000000 - 1 bytes | 0x800000 bytes |
| Large | Between 0x80000000 and 0x200000000 - 1 bytes | 0x1000000 bytes |
| Large | Between 0x200000000 and 0x800000000 - 1 bytes | 0x2000000 bytes |
| Large | Between 0x800000000 and 0x2000000000 - 1 bytes | 0x4000000 bytes |
| Large | Between 0x2000000000 and 0x8000000000 - 1 bytes | 0x8000000 bytes |
| Large | Between 0x8000000000 and 0x20000000000 - 1 bytes | 0x10000000 bytes |
| Large | Between 0x20000000000 and 0x80000000000 - 1 bytes | 0x20000000 bytes |
| Large | Equal or greater than 0x80000000000 | 0x40000000 bytes |

From looking up the size of the file on the table above, **BlackMatter** chooses the appropriate **ChaCha20** matrix used to encrypt files.

![alt text](/uploads/blackmatter63.PNG)

*Figure 65: Populating Encryption Fields In Shared Structure.*

Finally, the parent thread registers the target file handle with the global I/O completion port using **CreateIoCompletionPort**, sets the **fileHandle** field in the structure to the file handle and the **threadCurrentState** field to the initial state, and sends the shared structure to child threads using **PostQueuedCompletionStatus** to begin encryption.

![alt text](/uploads/blackmatter64.PNG)

*Figure 66: Sending shared structure to child threads.*

### Multithreading: Child Threads Encryption

Child threads communicate with each other and the main thread using **GetQueuedCompletionStatus** and **PostQueuedCompletionStatus**.

Each thread constantly polls for an I/O completion packet from the global I/O completion port. The packet received from **GetQueuedCompletionStatus** contains an file's **BlackmatterFileStruct** structure to be processed.

![alt text](/uploads/blackmatter65.PNG)

*Figure 67: Sending shared structure to child threads.*

The encryption process is divided into four states. The file's current state is recorded in the **threadCurrentState** of the shared structure.

#### I. State 0: Reading File

The first state reads a number of bytes specified by the **bytesToRead** field into the buffer at the **bufferToReadData** field using **ReadFile**.

If **ReadFile** throws the error **ERROR_IO_PENDING**, the malware enters an infinite loop of sleeping for 100ms and calling **ReadFile** until it succeeds.

If **ReadFile** throws the error **ERROR_HANDLE_EOF**, the malware sets the encryption state to 2, else the encryption state is set to 1.

![alt text](/uploads/blackmatter66.PNG)

*Figure 68: State 0: Reading file.*

#### II. State 1. Encrypt and Write File

The second state encrypts the buffer at the **bufferToReadData** field using its modified **ChaCha20** implementation.

After the encryption, the malware calls **WriteFile** to write the encrypted data back into the file.

If **ReadFile** throws the error **ERROR_IO_PENDING**, the malware enters an infinite loop of sleeping for 100ms and calling **WriteFile** until it succeeds.

If the skipped size is not zero, **BlackMatter** moves the file pointer ahead to the next chunk by adding that skipped size to the current pointer.

![alt text](/uploads/blackmatter67.PNG)

*Figure 69: State 1: Encrypting and writing file.*

If the skipped size is zero, the malware stops encrypting after the first 0x100000 bytes and moves to state 2.

##### BlackMatter Custom ChaCha20

I want to discuss a bit about the customized ChaCha20 implementation of **BlackMatter**, instead of just glancing over it and calling it "customized".

Full credit of this section goes to [Michael Gillespie](https://twitter.com/demonslay335) for figuring out this crypto implementation and helping me understand it!

It seems like the implementation of **BlackMatter v2** is the modified version of **CryptoPP's ChaCha20** implementation that can be found [here](https://github.com/weidai11/cryptopp/blob/bc7d1bafa1e8ac732396374f0bca94ab9f396f1c/chacha_simd.cpp#L569).

Unlike a lot of **ChaCha** implementation, this one utilizes the **__m128i** type to store the states in **xmm** regiters.

Despite allocating 124 bytes for the "matrix", **BlackMater** only uses the first 64 bytes and turns it into a 128-byte state by mirroring the first 64 bytes with the last 64 bytes.

After performing 20 rounds of flipping and rotating using that state, the malware generates a 128-byte stream to encrypt the data coming in.

![alt text](/uploads/blackmatter91.PNG)

*Figure 69: Custom ChaCha20 implementation.*

#### III. State 2. Write File Footer

This state is executed only when the file encryption is complete.

![alt text](/uploads/blackmatter68.PNG)

*Figure 70: State 2: Write file footer.*

The malware calls **WriteFile** to write the 132-byte buffer from the **fileFooter** field in the shared structure to the end of the file.

This buffer contains the **RSA_encrypted_ChaCha20_matrix_Checksum** and the **RSA_encrypted_ChaCha20_matrix** fields in the structure from [Cryptographic Keys Setup](#cryptographic-keys-setup), which are used to check if a file is encrypted and to decrypt it.

After this state, the malware moves to state 3.

#### IV. State 3. Clean Up

This is the last state in the file encryption process.

In this state, **BlackMatter** calls **NtClose** to close the file handle, calls **RtlFreeHeap** to free the shared structure buffer from memory, and increments the global **TOTAL_NUM_FILE_ENCRYPTED** value.

![alt text](/uploads/blackmatter69.PNG)

*Figure 71: State 3: Clean up.*

#### Child Thread Communication

In **BlackMatter's** multithreading setup, each child thread only handles one state in the encryption process.

After each state (beside the final state), the malware calls **PostQueuedCompletionStatus** to post the shared structure to the global I/O completion port with the updated encryption state. The next thread who receives it then processes that state before moving it forward.

![alt text](/uploads/blackmatter70.PNG)

*Figure 72: Child thread communication.*

### Exchange Mailbox Traversal

If the **MOUNT_VOL_AND_ENCRYPT_FLAG** in the configuration is set to true, **BlackMatter** encrypts the Exchange mailbox of the local user.

First, it calls **GetEnvironmentVariableW** to retrieve the Exchange installation path.

![alt text](/uploads/blackmatter71.PNG)

*Figure 73: Retrieving Exchange installation path.*

After retrieving the path, the malware checks to make sure it is in the **Program Files** directory (64-bit Exchange installation) and append **/Mailbox** to the path.

![alt text](/uploads/blackmatter72.PNG)

*Figure 74: Building full Exchange mailbox path.*

Finally, **BlackMatter** spawns threads to encrypt this path using the encryption scheme described above.

![alt text](/uploads/blackmatter73.PNG)

*Figure 75: Traversing and encrypting Exchange mailbox path.*

### Logical Drives Traversal

If the **MOUNT_VOL_AND_ENCRYPT_FLAG** in the configuration is set to true, **BlackMatter** mounts and encrypts all logical drives.

First, the malware enumerates through all volumes on the computer using **FindFirstVolumeW** and **FindNextVolumeW**. It calls **GetVolumePathNamesForVolumeNameW** to retrieve the path of the volume and processes the drive at that path.

![alt text](/uploads/blackmatter74.PNG)

*Figure 76: Volume enumeration.*

It only processes and encrypts drives with type **DRIVE_FIXED** or **DRIVE_REMOVABLE**.

If the current OS is Windows 7 or above, the malware calls **DeviceIoControl** to get the partition information of the target drive.

If the partition type of the drive is **PARTITION_STYLE_GPT**, **BlackMatter** sets some check with the partition type data and calls **SetVolumeMountPointW** to mount it.

If the partition type of the drive is **PARTITION_STYLE_MBR**, **BlackMatter** calls **SetVolumeMountPointW** to mount it.

![alt text](/uploads/blackmatter75.PNG)

*Figure 77: Mounting drives.*

If the current OS is earlier than Windows 7, the malware appends **/bootmgr** to the end of the drive path and calls **SetVolumeMountPointW** to mount it.

![alt text](/uploads/blackmatter76.PNG)

*Figure 78: Mounting bootmgr.*

Next, **BlackMatter** calls **GetLogicalDriveStringsW** to get the list of all logical drives on the system.

For each of these drives that are **DRIVE_REMOTE**, **DRIVE_FIXED**, or **DRIVE_REMOVABLE**, the malware spawns threads to encrypt this path using the encryption scheme described above.

If the drive type is **DRIVE_REMOTE**, **BlackMatter** impersonates the parent thread with the obtained token.

![alt text](/uploads/blackmatter77.PNG)

*Figure 79: Traversing and encrypting logical drives.*

### Network Shares Traversal

If the **NETWORK_ENCRYPT_FLAG** in the configuration is set to true, **BlackMatter** encrypts all network shares.

First, it retrieves the list of all DNS hostnames on the network through domain controllers.

**BlackMatter** calls **DsGetDcNameW** to obtain the domain controller information and **DsGetDcOpenW** to open a new domain controller enumeration operation.

![alt text](/uploads/blackmatter78.PNG)

*Figure 80: Open domain controller enumeration operation.*

By calling **DsGetDcNextW**, the malware enumerates through all domain controller on the network and adds it to an array.

![alt text](/uploads/blackmatter79.PNG)

*Figure 81: Enumerating domain controllers.*

Next, for each domain controller, **BlackMatter** calls **ADsOpenObject("LDAP://rootDSE", 0, 0, 1u, "{FD8256D0-FD15-11CE-ABC4-02608C9E7553}", &IADs_object)** to retrieve the **IADs** COM interface.

Using the **Get** function of the **IADs** interface, it gets the default naming context of the domain.

![alt text](/uploads/blackmatter80.PNG)

*Figure 82: Get domain default naming context.*

With the default naming context, **BlackMatter** builds the string **"LDAP://CN=Computers,[default naming context]"** and calls **ADsOpenObject** to retrieve an **IADsContainer** interface.

Using that interface, it calls **ADsBuildEnumerator** to create an enumerator object for the specified ADSI container object. Finally, using the enumerator, the malware calls **ADsEnumerateNext** to enumerate through all DNS hostnames from the domain controller.

![alt text](/uploads/blackmatter81.PNG)

*Figure 83: Enumerating DNS hostnames.*

With a list of DNS hostnames on the network, the malware calls **NetShareEnum** to start enumerating through each of them.

If the network share type is not special share reserved for interprocess communication (IPC\$) or remote administration of the server (ADMIN\$), the malware skips it and does not add it to the share list to encrypt.

![alt text](/uploads/blackmatter82.PNG)

*Figure 84: Checking network share type.*

If the network share type is special, the malware performs an additional check and skips the share if the network name is **"admin\$"** or **"\$c"**.

![alt text](/uploads/blackmatter83.PNG)

*Figure 85: Checking network name.*

Finally, **BlackMatter** fixes up the network paths and spawns threads to encrypt these paths using the encryption scheme described above.

![alt text](/uploads/blackmatter84.PNG)

*Figure 86: Traversing and encrypting network share.*

## Network Communication

If the **SEND_DATA_TO_SERVER_FLAG** in the configuration is set to true, **BlackMatter** sends data twice to remote servers, once prior to the encryption and once after the encryption.

Prior to the encryption, the malware sends information about the victim's machine to the servers.

It extracts information about the host and different disks on the system and builds the string using the format below.

``` JSON
{
   "bot_version":"%s",
   "bot_id":"%s",
   "bot_company":"%.8x%.8x%.8x%.8x%",
   "host_hostname":"%s",
   "host_user":"%s",
   "host_os":"%s",
   "host_domain":"%s",
   "host_arch":"%s",
   "host_lang":"%s",
   "disks_info":[
      {
         "disk_name":"%s", // for each disk
         "disk_size":"%u",
         "free_size":"%u"
      }
   ]
}
```

Below is an example of the payload generated on my VM.

``` JSON
{
   "bot_version":"2.0",
   "bot_id":"e6175d544e3816664c0c6297cf8bcb18",
   "bot_company":"00000000000000000000000000000000",
   "host_hostname":"MSEDGEWIN10",
   "host_user":"IEUser",
   "host_os":"Windows 10 Enterprise Evaluation",
   "host_domain":"WORKGROUP",
   "host_arch":"x64",
   "host_lang":"en-US",
   "disks_info":[
      {
         "disk_name":"C",
         "disk_size":"40957",
         "free_size":"17290"
      },
      {
         "disk_name":"Z",
         "disk_size":"487290",
         "free_size":"304117"
      }
   ]
}
```

![alt text](/uploads/blackmatter85.PNG)

*Figure 87: Host format string.*

This buffer is encrypted and sent to remote servers specified in the **REMOTE_SERVER_URLS** field in the configuration.

After the file encryption, the malware sends encryption stats to the servers.

The information about encryption stats is built into a string using the format below.

``` JSON
{
   "bot_version":"%s",
   "bot_id":"%s",
   "bot_company":"%.8x%.8x%.8x%.8x%",
   "stat_all_files":"%u",
   "stat_not_encrypted":"%u",
   "stat_size":"%s",
   "execution_time":"%u",
   "start_time":"%u",
   "stop_time":"%u"
}
```

![alt text](/uploads/blackmatter86.PNG)

*Figure 88: Encryption stats format string.*

When sending these data to remote servers, **BlackMatter** first encrypts it using the **AES** key from the configuration and **Base64-encodes** it.

![alt text](/uploads/blackmatter87.PNG)

*Figure 89: Data encryption and encoding.*

Next, it randomly generates HTTP object names and POST request data.

**BlackMatter** uses the following user agent.

``` http
AppleWebKit/587.38 (KHTML, like Gecko)
```

It also decrypts and uses this POST request header.

``` http
Accept: */*
Connection: keep-alive
Accept-Encoding: gzip, deflate, br
Content-Type: text/plain
```

Finally, the malware uses the typical HTTP WinAPI calls such as **InternetOpenW** to obtain an internet handle, **InternetConnectW** to obtain a connection handle with a target URL, **HttpOpenRequestW** to open a POST request, and **HttpSendRequestW** to send the encrypted data.

![alt text](/uploads/blackmatter88.PNG)

*Figure 90: Sending data to remote servers.*

## Weird Threading Stuff

I want to dedicate a section to talk about this because it annoys the hell out of me.

It seems like **BlackMatter** loves to use this one trick to spawn a single thread to execute a single WinAPI call.

![alt text](/uploads/blackmatter89.PNG)

*Figure 91: Single threading with extra steps.*

I must admit that this does work, and I can definitely see the reason behind this. The malware wants to make API calls while impersonating as a different process using the token it gets from [here](#retrieving-token-to-impersonate-with-process-injection) to be stealthier.

So why am I annoyed? It's just really extra.

This whole part of code can be reduced to a single **GetUserNameW** call, which is why it is so inefficient. Moreover, they have a ransomware running that encrypts a system in less than a minute. Trying to be stealthy to call things like **GetUserNameW** and **GetDriveTypeW** might just be an overkill.

Or maybe this method is fine and I'm just grumpy cause this ransomware is so damn long to fully analyze lmao.

## References

https://github.com/weidai11/cryptopp/blob/bc7d1bafa1e8ac732396374f0bca94ab9f396f1c/chacha_simd.cpp#L569

https://github.com/sisoma2/malware_analysis/tree/master/blackmatter

https://github.com/advanced-threat-research/DarkSide-Config-Extract

https://www.fireeye.com/content/dam/fireeye-www/current-threats/pdfs/wp-ransomware-protection-and-containment-strategies.pdf

https://www.installsetupconfig.com/win32programming/networkmanagementapis16_41.html

https://www.youtube.com/watch?v=R4xJou6JsIE

https://blog.digital-investigations.info/2021-08-05-understanding-blackmatters-api-hashing.html