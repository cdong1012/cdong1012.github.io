---
title: MountLocker Ransomware
categories:
  - Reverse Engineering
description: Malware Analysis Report - MountLocker Ransomware
---

# MountLocker Ransomware 


## Overview


This is my report for a **MountLocker Ransomware v5.0** sample, which is used by **XingLocker** ransomware group.

This ransomware uses a hybrid-cryptography scheme of **RSA-2048** and **ChaCha20** to encrypt files and protect its keys. Unlike other ransomware, **MountLocker** encrypts all of the **ChaCha20** keys with a global **ChaCha20** key before encrypting this global key with its **RSA-2048** public key. The encrypted global key and the corresponding encrypted **ChaCha20** key are appended at the end of each encrypted file.


This version includes a new worm feature that lets it self-propagate to other PCs on the network using **IDirectorySearch** and **IWbemServices** COM interfaces.


**MountLocker** has a sophisticated multithreading scheme, but its performance suffers from thread starvation due to recursive file traversal. 

I won't waste my time explaining why recursive file traversal is terrible anymore cause I have made my points through the last few reports. Please feel free to check out my [Darkside analysis](https://chuongdong.com/reverse%20engineering/2021/05/06/DarksideRansomware/) if you want to better understand the theory behind it!


![alt text](/uploads/mountlocker1.PNG)

*Figure 1: XingLocker Ransomware leak site.*


## IOCS

This v5.0 sample is a 64-bit .exe file. 

**MD5**: 3808f21e56dede99bc914d90aeabe47a

**SHA256**: 4a5ac3c6f8383cc33c795804ba5f7f5553c029bbb4a6d28f1e4d8fb5107902c1

**Sample**: https://bazaar.abuse.ch/sample/4a5ac3c6f8383cc33c795804ba5f7f5553c029bbb4a6d28f1e4d8fb5107902c1/


![alt text](/uploads/mountlocker2.PNG)

*Figure 2: VirusTotal information.*


## Ransom Note

The ransom note is written in HTML format and is dropped into **RecoveryManual.html** files on the system.

The client ID embedded inside the ransom note is generated from the victim's computer name and a hard-coded string in memory.

![alt text](/uploads/mountlocker3.PNG)

*Figure 3: MountLocker ransom note.*


## Performance

**MountLocker** has pretty average performance and does not fully utitlize the machine's processing power.

![alt text](/uploads/mountlocker4.PNG)

*Figure 4: ANY.RUN sandbox result.*


## Static Code Analysis


### Command Line Parameters

**MountLocker** can be ran with or without command line parameters. The ransomware first checks and parse the given parameters to modify its functionalities accordingly.

![alt text](/uploads/mountlocker5.PNG)

*Figure 5: Parsing command line parameters.*


Below is the list of arguments that can be supplied by the operators:

| Argument   | Description |
| -------- | ----------- |
| /LOGIN= | Network username (for network encryption and worm) |
| /PASSWORD= | Network password (for network encryption and worm) |
| /CONSOLE |  Logging through console |
| /NODEL |  No self-deletion |
| /NOKILL |  No service and process killing |
| /NOLOG |  No logging through file (this is hard-coded to be **FALSE** in this sample) |
| /SHAREALL |  Encrypting all shared resources (except **"\\ADMIN$"**) |
| /NETWORK |  **Worm network type:**<br> - ***w*** = Windows Management Instrumentation (WMI)<br> - ***s*** = service (requires **ADMIN** creds)<br> - others = unknown or default |
| /PARAMS= |  Command line parameters to launch executable with on other PCs (worm) |
| /TARGET= |  Path to a file or a directory to be encrypted specifically<br>*There can be multiple target arguments* |
| /FAST= |  Buffer size for fast encryption (default: 0x10000000 bytes) |
| /MIN= |  Minimum file size to encrypt (default: 0 bytes) |
| /MAX= |  Maximum file size to encrypt (default: 0 bytes) |
| /FULLPD |  Does not avoid encrypting **Program Files**, **Program Files (x86)**<br>**ProgramData**, and **SQL** |
| /MARKER= |  Marker file name to drop in each encrypted drive |
| /NOLOCK= | **Avoid encrypting:** <br> - ***L***: Local<br> - ***N***: Network<br> - ***S***: Network shared resources |


### Logging


The ransomware has two different ways to log its operations, and each can be enabled through setting the command line arguments **/CONSOLE** to 1 and **/NOLOG** to 0.

In this particular sample, **/NOLOG** flag's value is hard-coded to be 0, so it always records and drops a log file on the victim's system.


When the **/NOLOG** flag is 0, **MountLocker** extracts the current executable's file path, append **.log** to the end, and use that as the log file path.


![alt text](/uploads/mountlocker6.PNG)

*Figure 6: Creating log file in current directory.*


When the **/CONSOLE** flag is 1, **MountLocker** will also log through console standard output stream. It calls **AllocConsole** and **GetStdHandle(STD_OUTPUT_HANDLE)** to allocate the console and get a handle to the standard output stream.

To write to this console, it calls **WriteConsoleW** with this handle.

![alt text](/uploads/mountlocker7.PNG)

*Figure 7: Creating log file in current directory.*


The beginning of the log tells us the version of the specific **MountLocker** sample, and in this case, the version is 5.0.


It also extracts and records information about the victim's system such as the number of processors, total system memory, Windows version, system architecture, ...


![alt text](/uploads/mountlocker9.PNG)

*Figure 8: Logging system information.*


All file and network operations (enumeration, skipping, encrypting, error) are recorded this way.


![alt text](/uploads/mountlocker8.PNG)

*Figure 9: MountLocker log file.*


### Terminating Services


If the **/NETWORK** argument is not provided, the malware will run in local mode.

In this mode, if the **/NOKILL** argument is 1, it enumerates and kills all services with these strings in their name.

``` python
"SQL", "database", "msexchange"
```

First, it calls **OpenSCManagerA** to obtain a handle to the service control manager and calls **EnumServicesStatusA** to enumerate all Win32 services with status *SERVICE_ACTIVE*.


![alt text](/uploads/mountlocker10.PNG)

*Figure 10: Enumerating through all active services.*


If a service contains any of the three strings above, **MountLocker** will terminate it by calling **OpenServiceA** to obtain a service control handle and calling **ControlService** to send a control stop code. It then continuously loops until the service's state is *SERVICE_CONTROL_STOP* to make sure the service is fully terminated.


![alt text](/uploads/mountlocker11.PNG)

*Figure 11: Sending control stop code to terminate service.*


### Terminating Processes


If it's running in local mode and the **/NOKILL** argument is 1, **MountLocker** will enumerate and kill all processes with these strings in their name.

``` python
"msftesql.exe", "sqlagent.exe", "sqlbrowser.exe", "sqlwriter.exe", "oracle.exe", "ocssd.exe", 
"dbsnmp.exe", "synctime.exe", "agntsvc.exe", "isqlplussvc.exe", "xfssvccon.exe", "sqlservr.exe", 
"mydesktopservice.exe", "ocautoupds.exe", "encsvc.exe", "firefoxconfig.exe", "tbirdconfig.exe", 
"mydesktopqos.exe", "ocomm.exe", "mysqld.exe", "mysqld-nt.exe", "mysqld-opt.exe", "dbeng50.exe", 
"sqbcoreservice.exe", "excel.exe", "infopath.exe", "msaccess.exe", "mspub.exe", "onenote.exe", 
"outlook.exe", "powerpnt.exe", "sqlservr.exe", "thebat.exe", "steam.exe", "thebat64.exe", "thunderbird.exe", 
"visio.exe", "winword.exe", "wordpad.exe", "QBW32.exe", "QBW64.exe", "ipython.exe", "wpython.exe", 
"python.exe", "dumpcap.exe", "procmon.exe", "procmon64.exe", "procexp.exe", "procexp64.exe"
```

The ransomware first calls **ZwQuerySystemInformation** with the information class of *SystemProcessInformation* to get an array of **SYSTEM_PROCESS_INFORMATION** structures. It enumerates through each running process, avoids its own process, and starts terminating processes in the kill list.


![alt text](/uploads/mountlocker12.PNG)

*Figure 12: Enumerating through all active processes.*

To check and kill a process, it loops through the **PROCESS_TO_KILL** list and compares the process name. If the process name is in the list, it calls **OpenProcess** to get the handle of that process and terminates it using **TerminateProcess**.


![alt text](/uploads/mountlocker13.PNG)

*Figure 13: Terminating processes that are in the kill list.*

### Generating Global ChaCha20 Key


Next, it randomly generates the global **ChaCha20** key. The randomization is done through calling the **rdtsc** instruction to get the processor time stamp and xoring its least significant byte to generate each byte in the key.

After generating the global key, the ransomware copies the key to another global buffer in memory and encrypts this new buffer using the hard-coded **RSA-2048** key.


![alt text](/uploads/mountlocker19.PNG)

*Figure 14: Randomly generate global ChaCha20 key and encrypt it with RSA-2048.*


**MountLocker** later uses this global **ChaCha20** key to encrypt and protect its **ChaCha20** keys instead of using **RSA-2048**. Since **RSA-2048** encryption is only performed once, there is some performance advantage with this hybrid-cryptography scheme since **RSA** is quite slow compared to **ChaCha20**.


### Encryption


#### Creating Encrypting Threads


Despite having different schemes for different drive types and targets, the encryption functionality is pretty much the same. 


**MountLocker** has a specific function that takes in a drive/file name to encrypt and a function to enumerate through it as parameters.


This function first passes the enumerating function and the target name to a custom structure before spawning a thread to begin the encryption.

This thread acts as the main thread in the encryption, which recursively enumerates and provides files for children threads to encrypt.


![alt text](/uploads/mountlocker14.PNG)

*Figure 15: Spawning main thread.*


The main thread function calls **CreateEventA** to create an event handler for each child thread to later send them file information through calling **SetEvent**.

Only 2 children worker threads are spawned, and these threads loops and waits to receive files from the main thread to encrypt. The main thread will begin feeding them files by calling the enumeration function in the custom structure above and enumerating through the target folder.


![alt text](/uploads/mountlocker15.PNG)

*Figure 16: Main thread spawning children threads and starting file enumeration.*


#### Children Worker Threads


Once spawned, each worker thread receives a shared structure with the main thread, and it constantly loops to check for the encrypt signal is 1 in this shared structure.


Due to synchronization through sharing a common structure among threads, the child thread calls **_InterlockedExchange** to atomically extract the encrypt signal to check if it's allowed to encrypt.


As it finds files to encrypt, the main thread adds the file name to the shared structure and sets the encrypt signal for the child thread to process that file.


![alt text](/uploads/mountlocker16.PNG)

*Figure 17: Child thread waiting for encrypt signal to encrypt files.*


After receiving the file information, the worker thread creates a structure to store file information such as filename, encrypted filename, file handle, file size, ... 


It will then checks to see if it has priviledge to open the file and retrieve the file size.


![alt text](/uploads/mountlocker17.PNG)

*Figure 18: Checking if file can be opened.*


Next, it randomly generates the file's **ChaCha20** key and appends it to the file structure above. The randomization is done through calling the **rdtsc** instruction similar to the global **ChaCha20** key generation.


![alt text](/uploads/mountlocker18.PNG)

*Figure 19: Randomly generating ChaCha20 key for each file.*


After generating the **ChaCha20** file key, the worker thread creates a 313-byte buffer that stores the file marker string **"lock2"** in little endian, the fast encryption size, the encrypted **ChaCha20** global key, and the encrypted **ChaCha20** file key. This buffer is appended at the end of the to-be-encrypted file.


![alt text](/uploads/mountlocker20.PNG)

*Figure 20: Generating key buffer and writing it at the end of the file.*


Here is the layout of the key buffer at the end of an encrypted file.

![alt text](/uploads/mountlocker21.PNG)

*Figure 21: Key buffer layout.*


File encryption is pretty standard. The worker thread encrypts a 0x100000-byte chunk at a time until it has encrypted **FAST_CRYPT_SIZE** bytes or ran out of bytes to encrypt.

It uses **ReadFile** to read file content into a buffer, encrypts it using the **ChaCha20** file key, and writes it back using **WriteFile**. Because encryption is performed on the same file, **SetFilePointerEx** is called to adjust the file pointer after reading and writing.


![alt text](/uploads/mountlocker22.PNG)

*Figure 22: ChaCha20 File Encryption.*


I won't analyze the **ChaCha20** function cause **MountLocker** basically just uses [this CRYPTOGAMS library by OpenSSL](https://github.com/dot-asm/cryptogams/blob/master/x86_64/chacha-x86_64.pl).


#### Main Thread Enumeration


**MountLocker** uses the same function for file traversal for network drives, network shares, and local drives.


Before traversing a drive, the ransomware checks if a marker file name is provided from the **/MARKER=** command line argument. If it is, **MountLocker** creates an empty file with this marker file name in the to-be-encrypted drive before enumerating it. This is mainly for marking which drive has been encrypted.


![alt text](/uploads/mountlocker23.PNG)

*Figure 23: Creating drive marker file.*


To enumerate through folders, **MountLocker** calls **FindFirstFileW** and **FindNextFileW**.
When enumerating through network servers, it will use **WNetOpenEnumW** and **WNetEnumResourceW** instead. 

![alt text](/uploads/mountlocker24.PNG)

*Figure 24: Recursive file traversal.*


The ransomware also calls a function to checks if it should encrypt each file/folder that it finds.


When processing a folder, the checking function will check for the following things. If any of these is true, the folder is skipped.

```
  - If folder name is "." or ".."
  - If folder name is in the FOLDER_TO_AVOID list
  - If folder name is "Program Files", "Program Files (x86)", "ProgramData", or "SQL"
  - If calling CreateFileW on the folder fails.
  - If folder's reparse tag is not IO_REPARSE_TAG_MOUNT_POINT (folder is a mount point) 
  or IO_REPARSE_TAG_SYMLINK (folder is a symbolic link)\
  - If folder name is in a share name format
  - If folder is a mount point and is visible
```


Below is the **FOLDER_TO_AVOID** list.

``` python
":\\Windows\\", ":\\System Volume Information\\", ":\\$RECYCLE.BIN\\", ":\\SYSTEM.SAV", ":\\WINNT", 
":\\$WINDOWS.~BT\\", ":\\Windows.old\\", ":\\PerfLog\\", ":\\Boot", ":\\ProgramData\\Microsoft\\", 
":\\ProgramData\\Packages\\", "$\\Windows\\", "$\\System Volume Information\\", "$\\$RECYCLE.BIN\\", 
"$\\SYSTEM.SAV", "$\\WINNT", "$\\$WINDOWS.~BT\\", "$\\Windows.old\\", "$\\PerfLog\\", "$\\Boot", 
"$\\ProgramData\\Microsoft\\", "$\\ProgramData\\Packages\\", "\\WindowsApps\\", "\\Microsoft\\Windows\\", 
"\\Local\\Packages\\", "\\Windows Defender", "\\microsoft shared\\", "\\Google\\Chrome\\", "\\Mozilla Firefox\\", 
"\\Mozilla\\Firefox\\", "\\Internet Explorer\\", "\\MicrosoftEdge\\", "\\Tor Browser\\", "\\AppData\\Local\\Temp\\"
```

If the folder is valid and there is no ransom note file in the folder yet, **MountLocker** will drop a ransom note in the folder.


![alt text](/uploads/mountlocker25.PNG)

*Figure 25: Dropping ransom note.*


When processing a file, the checking function checks for the following things. If any of these is true, the file is skipped.

```
  - If file size is less than MIN_CRYPT_SIZE (if MIN_CRYPT_SIZE is provided)
  or if file size is larger than MAX_CRYPT_SIZE (if MAX_CRYPT_SIZE is provided)
  - If file name is "RecoveryManual.html", "bootmgr", or has the encrypted file extension.
  - If file extension is in the EXTENSION_TO_AVOID list
```

Below is the **EXTENSION_TO_AVOID** list.

``` python
"exe", "dll", "sys", "msi", "mui", "inf", "cat", "bat", "cmd", "ps1", "vbs", "ttf", "fon", "lnk"
```

If the file is valid, the ransomware's main thread will populate the shared file structure with the file name for its worker thread to encrypt.

Because of synchronization concerns, the main thread also has to call **WaitForSingleObject** and **_InterlockedExchange** to wait until it has access to the shared structure.

After populating the file structure, it calls **SetEvent** to signal the event for worker threads to encrypt.


![alt text](/uploads/mountlocker26.PNG)

*Figure 26: Calling **SetEvent** to signal file encryption.*


### Worm Property


Similar to **WannaCry** and **Ryuk**, this **MountLocker** sample is a combination of ransomware and worm with the ability to self-propagate to other hosts in the network.


Unlike **WannaCry**, this ransomware does not use any fancy 0-day but instead just COM interfaces such as **IDirectorySearch** and **IWbemServices** to spread and execute itself.


**MountLocker** has this structure that is shared among all worm threads.

``` cpp
struct WORM_STRUCT
{
  _QWORD function; // function to launch ransomware remotely
  _QWORD func_param; // function's parameter
  HANDLE hEvent; // worm event
  HANDLE hSemaphore; // worm semaphore
};
```

First, memory is allocated for this structure, and the event handle and semaphore handle are created. The ransomware launching function and its parameter is originally left to be null initially.

**MountLocker** creates 8 threads to execute this worm property.


![alt text](/uploads/mountlocker27.PNG)

*Figure 27: Populating worm struct and creating worm threads.*


Each of these threads waits for the event to be signal by the main thread before calling the worm function to execute the ransomware remotely. The main thread will set this worm function accordingly before signalling the event.


![alt text](/uploads/mountlocker28.PNG)

*Figure 28: Worm worker threads.*


After creating these worker threads, the main thread begins enumerating the Windows domain that the current host is in.


This is accomplished through calling **NetGetDCName** to get the name of the primary domain controller and append this name after the string **"LDAP://"**.


![alt text](/uploads/mountlocker29.PNG)

*Figure 29: Building LDAP path.*

[Lightweight Directory Access Protocol (LDAP)](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol) is a protocol to communicate and query several different types of directories, and in this case, **MountLocker** uses it to make Active Directory query requests to the primary domain controller.


It calls **ADsOpenObject** with the newly built **ADsPath** string and provides the credential (username and password) from the **/LOGIN=** and **/PASSWORD=** arguments. The **RIID** provided is **{109BA8EC-92F0-11D0-A790-00C04FD8D5A8}**, and through this call, the ransomware retrieves the **IDirectorySearch** interface.


This trick to query **IDirectorySearch** is previously used by Trickbot as explained by Vitali [here](https://www.vkremez.com/2017/12/lets-learn-introducing-new-trickbot.html).

![alt text](/uploads/mountlocker30.PNG)

*Figure 30: Querying **IDirectorySearch** interface.*


This interface can be used to execute a search for all domain controllers through its **IDirectorySearch::ExecuteSearch** function which return an ADs search handle.


**MountLocker** calls **IDirectorySearch::GetFirstRow** and **IDirectorySearch::GetNextRow** to enumerate through all the searches, passing each search into a function to extract its domain controller information.


![alt text](/uploads/mountlocker31.PNG)

*Figure 31: Enumerating through ADs searches to extract domain controller information.*


For each of these search handles, **MountLocker** then calls **IDirectorySearch::GetColumn** with the column name **"name"** to retrieve the corresponding **ADS_SEARCH_COLUMN** structure at this row.


This structure contains an array of **ADSVALUE** structures, and each of these structures contains a DN string of a directory service object in the Active Directory. This Distinguished Name (DN) string is basically a name to identify another PC in the network.

![alt text](/uploads/mountlocker32.PNG)

*Figure 32: Extracting all DN string of other PCs in the network.*

When a DN string of a PC is extracted, it's passed into a function where the ransomware will use it as the function parameter in the **WORM_STRUCT** structure. The structure's function is set to a specific function that drops and launches the sample remotely. **SetEvent** is called to execute this function after the **WORM_STRUCT** structure is fully populated.


![alt text](/uploads/mountlocker33.PNG)

*Figure 33: Setting up WORM_STRUCT and signal the worm event.*


#### Worm Dropping Function

First, the worm thread will try to establish a connection to the remote target PC by calling **WNetAddConnection2W** and provice the username and password from the **/LOGIN=** and **/PASSWORD=** arguments.


![alt text](/uploads/mountlocker34.PNG)

*Figure 34: Establishing connection with remote PC.*


Next, memory is allocated for a custom structure. I just call this **WORM_REMOTE_STRUCT**.

``` cpp
struct WORM_REMOTE_STRUCT
{
  LPCWSTR rem_exe_path; // remote executable path
  CHAR *launch_exe_cmd; // command line to launch executable
  CHAR *PC_name; // remote PC name
  CHAR *elevated_PC_path; // Elevated PC path to launch executable
  DWORD API_result; // result value
  DWORD last_error; // last error value
  CHAR *exe_name; // executable name
};
```

It then populates this structure. The executable name is a number retrieved from **GetTickCount**, and the path on the host to drop the ransomware is set to **"C:\\ProgramData"**.

![alt text](/uploads/mountlocker35.PNG)

*Figure 35: Populating **WORM_REMOTE_STRUCT**.*


The **drop_ransomware** function checks if the DN string contains either of the share names with higher priviledge **"\\ADMIN\$"** and **"\\IPC\$"**. If it does, then **MountLocker** uses that as the main path in the command to launch the executable. If it doesn't, then it just uses the normal path.


The ransomware sample is set to be launched with the **/NOLOG** parameter and any arguments provided in the original **/PARAMS=** argument.

Finally, it drops the ransomware on the target PC by calling **CopyFileW**.


![alt text](/uploads/mountlocker36.PNG)

*Figure 36: Dropping the ransomware on the target PC.*


Not only does **MountLocker** drops the ransomware executable on the target PC but it also enumerates through the PC's shared resources in the PC's network by calling **NetShareEnum**. After finding the path to each shared resource, the ransomware calls **drop_ransomware** to drop the executable in the shared resource's system.


![alt text](/uploads/mountlocker37.PNG)

*Figure 37: Dropping the ransomware on the target PC's shared resources.*


#### Worm Launching Function


**MountLocker** has two different ways to launch the executable on the remote host.

If the **/NETWORK** argument provided is ***s***, it launches the executable through a service.

First, this full **cmd.exe** command is built.

``` powershell
cmd.exe /c start "ransomware_path PARAMS_VALUE /NOLOG"
```

Then, the ransomware calls **OpenSCManagerW** to establish a connection to the service control manager on the target PC. Using this handle, it calls **CreateServiceW** with the command above as its *lpBinaryPathName* parameter to create a service handle and calls **StartServiceW** to launch it.


![alt text](/uploads/mountlocker38.PNG)

*Figure 38: Launching ransomware on remote host using Service.*


If the **/NETWORK** argument provided is ***w***, it launches the executable through **Windows Management Instrumentation (WMI)**.


First, **MountLocker** retrieves the **IWbemServices** interface. This is done by calling **CoCreateInstance** with the CLSID **{4590F811-1D3A-11D0-891F-00AA004B2E24}** to retrieve an **IWbemLocator** object.

Using this **IWbemLocator** object, it calls the **IWbemLocator::ConnectServer** to connect with the PC's **ROOT\CIMV2** namespace and obtain an **IWbemServices** object.


![alt text](/uploads/mountlocker39.PNG)

*Figure 39: Connecting to **ROOT\CIMV2** namespace through COM objects.*


From here, **MountLocker** sets up an appropriate **SEC_WINNT_AUTH_IDENTITY_A** structure with the given username and password. It then calls **CoSetProxyBlanket** to set the authentication information for this **IWbemServices** object.


![alt text](/uploads/mountlocker40.PNG)

*Figure 40: Setting the authentication information for the **IWbemServices** object.*


Using this **IWbemServices** object, the ransomware calls the **IWbemServices::GetObjectA** function with the **"Win32_Process"** path to get **IWbemClassObject** object corresponding to Windows32 processes.

Next, using this **"Win32_Process"** object, it then calls the **IWbemClassObject::GetMethod** function with the **"Create"** method name to get an **IWbemClassObject** object corresponding to the method to create a process.


With this method object, it calls the **IWbemClassObject::SpawnInstance** to create a new instance of the class.


![alt text](/uploads/mountlocker41.PNG)

*Figure 41: Retrieving the COM object to create a Windows32 process.*


Since the **Win32_Process::Create** requires a valid value for the command line in-parameter to execute properly, **MountLocker** calls the **IWbemClassObject::Put** function to set the value of the command line to the launching command that it has built above.


![alt text](/uploads/mountlocker42.PNG)

*Figure 42: Setting valid value for command line in-parameter.*


Finally, it calls **IWbemServices::ExecMethod** to create a Win32 process running the **"cmd.exe"** command above. It also checks to see if the new process is created successfully or not by checking if the process's ID is changed through calling **IWbemClassObject::Get**.


![alt text](/uploads/mountlocker43.PNG)

*Figure 43: Launching ransomware remotely using **Win32_Process::Create**.*



If any of these steps to drop and launch the executable fails, **MountLocker** just resorts to using **WNetOpenEnumW** and **WNetEnumResourceW** to enumerate through the victim's network and drops the ransomware in a similar fashion.


### Self-Deletion


If the **/NODEL** argument is set to 0, **MountLocker** will delete its own executable.


First, it creates a **.bat** file in the **TEMP** folder with a random name from **GetTickCount**.

It writes this command into this **.bat** file, which clears Read-only, System, and Hidden file attribute from the ransomware executable, forces deletes the executable quietly if it exists, and deletes the bat file.

``` powershell
attrib -s -r -h %1
:l
del /F /Q %1
if exist %1 goto l
del %0
```

Next, **MountLocker** builds the command line string to execute the **.bat** file with the executable path as the parameter and finally calls **CreateProcessW** to delete itself.


![alt text](/uploads/mountlocker44.PNG)

*Figure 44: Self-deletion.*


## YARA rule

``` yara
rule MountLocker5_0 {
	meta:
		description = "YARA rule for MountLocker v5.0"
		reference = "http://chuongdong.com/reverse%20engineering/2021/05/23/MountLockerRansomware/"
		author = "@cPeterr"
		tlp = "white"
	strings:
		$worm_str = "========== WORM ==========" wide
		$ransom_note_str = ".ReadManual.%0.8X" wide
		$version_str = "5.0" wide
		$chacha_str = "ChaCha20 for x86_64, CRYPTOGAMS by <appro@openssl.org>"
		$chacha_const = "expand 32-byte k"
		$lock_str = "[OK] locker.file > time=%0.3f size=%0.3f KB speed=%" wide
		$bat_str = "attrib -s -r -h %1"
		$IDirectorySearch_RIID = { EC A8 9B 10 F0 92 D0 11 A7 90 00 C0 4F D8 D5 A8 }
	condition:
		uint16(0) == 0x5a4d and all of them
}
```


## References

https://blogs.blackberry.com/en/2020/12/mountlocker-ransomware-as-a-service-offers-double-extortion-capabilities-to-affiliates

https://zawadidone.nl/2020/11/26/mount-locker-ransomware-analysis.html

https://www.vkremez.com/2017/12/lets-learn-introducing-new-trickbot.html

https://github.com/Finch4/Malware-Analysis-Reports/tree/main/MountLocker

https://github.com/dot-asm/cryptogams/blob/master/x86_64/chacha-x86_64.pl

https://www.bleepingcomputer.com/news/security/mountlocker-ransomware-uses-windows-api-to-worm-through-networks/
