---
title: Diavol Ransomware
categories:
  - Reverse Engineering
description: Malware Analysis Report - Diavol Ransomware
---

# Diavol Ransomware

## Contents

- [Diavol Ransomware](#diavol-ransomware)
  - [Contents](#contents)
  - [Overview](#overview)
  - [IOCS](#iocs)
  - [Ransom Note](#ransom-note)
- [Static Code Analysis](#static-code-analysis)
  - [Anti-Analysis: Launching Functions with Shellcode](#anti-analysis-launching-functions-with-shellcode)
  - [Command-line Arguments](#command-line-arguments)
  - [Bot ID Generation](#bot-id-generation)
  - [Hard-coded Configuration](#hard-coded-configuration)
  - [Bot Registration](#bot-registration)
  - [Configuration Overriding](#configuration-overriding)
  - [Stopping Services](#stopping-services)
  - [Terminating Processes](#terminating-processes)
  - [RSA Initialization](#rsa-initialization)
  - [Finding Drives To Encrypt](#finding-drives-to-encrypt)
  - [Scanning Target Network Shares Through SMB](#scanning-target-network-shares-through-smb)
  - [Scanning Network Shares In ARP Table Through SMB](#scanning-network-shares-in-arp-table-through-smb)
  - [Encryption: Target File Enumeration](#encryption-target-file-enumeration)
  - [Encryption: Remote File Enumeration Through SMB](#encryption-remote-file-enumeration-through-smb)
  - [Encryption: System Drives Enumeration](#encryption-system-drives-enumeration)
  - [Encryption: File Encryption](#encryption-file-encryption)
  - [Shadow Copies Deletion](#shadow-copies-deletion)
  - [Changing Desktop Image](#changing-desktop-image)
  - [Self Deletion](#self-deletion)
  - [Logging](#logging)
  - [References](#references)

## Overview

This is my analysis for the **DIAVOL Ransomware**.

**DIAVOL** is a relatively new ransomware that uses a unique method with shellcode to launch its core functions and **RSA** to encrypt files.

The malware contains a hard-coded configuration that stores informations such as files to encrypt and **RSA** public key, but it can also requests these informations from the threat actor's remote server.

Unlike most major ransomware, this new malware's encryption scheme is relatively slow due to its recursive method for file traversal.

![alt text](/uploads/diavol01.PNG)

*Figure 1: DIAVOL Post-Infection.*

## IOCS

Huge shout-out to [Curated Intelligence](https://twitter.com/CuratedIntel) for providing this sample.

The analyzed sample is a 64-bit Windows executable.

**MD5**: f4928b5365a0bd6db2e9d654a77308d7

**SHA256**: ee13d59ae3601c948bd10560188447e6faaeef5336dcd605b52ee558ff2a8588

**Sample**: [MalwareBazaar](https://bazaar.abuse.ch/sample/ee13d59ae3601c948bd10560188447e6faaeef5336dcd605b52ee558ff2a8588/)

![alt text](/uploads/diavol02.PNG)

*Figure 2: VirusTotal Result.*

## Ransom Note

The content of the default ransom note is stored in plaintext in **DIAVOL's** configuration. The malware can also request a ransom note from its remote server and override the default with that.

**DIAVOL's** ransom note filename is **README-FOR-DECRYPT.txt**.

![alt text](/uploads/diavol03.PNG)

*Figure 3: DIAVOL's Ransom Note.*

# Static Code Analysis

## Anti-Analysis: Launching Functions with Shellcode

For anti-analysis, **DIAVOL** loads shellcode containing its core functions into memory and executes it dynamically, which makes static analysis a bit harder.

First, the malware calls **VirtualAlloc** to allocate two memory buffers to later load these shellcodes in.

![alt text](/uploads/diavol04.PNG)

*Figure 4: Allocating Shellcode Buffers.*

When **DIAVOL** wants to execute a certain functionality, it calls a function to load the shellcode into memory and executes a **call** instruction to transfer control to the shellcode.

![alt text](/uploads/new_diavol05.PNG)

*Figure 5: Loading & Executing Shellcode.*

First, to load shellcode into memory, **DIAVOL** extracts the bitmap image corresponds to the given resource name by calling **LoadBitmapW**, **CreateCompatibleDC**, **SelectObject**, and **GetObjectW**.

Next, it calls **GetDIBits** to retrieve the bits of the bitmap image and copies them into the shellcode buffer as a DIB.

![alt text](/uploads/diavol06.PNG)

*Figure 6: Loading Shellcode into memory.*

Unlike normal shellcode, **DIAVOL's** don't manually walk the PEB to resolve its imports dynamically. The malware loads a "JPEG" with the same name in the resource section, extracts a list of imported functions with their corresponding DLL, and manually calls **LoadLibraryA** and **GetProcAddress** to resolve it for the shellcode. The resolved API addresses are stored at the end of the buffer, so the shellcode can make calls to those APIs using their exact offsets, which makes the loaded payload position-independent.

![alt text](/uploads/diavol07.PNG)

*Figure 7: Resolving API Addresses For Shellcode.*

Below is the bitmap and the imported API list extracted from **Resource Hacker**.

![alt text](/uploads/diavol08.PNG)

*Figure 8: DIAVOL Resource Section.*

Because each shellcode should be position-independent, we can simply load it into IDA for static analysis after extraction. However, the API addresses won't make sense when IDA loads the shellcode because they are relative to where the DLLs are in the malware's memory.

![alt text](/uploads/diavol09.PNG)

*Figure 9: Loading Shellcode Into IDA.*

To fix this, we just need to rename the API addresses in the order that they appear in the corresponding JPEG resource. After renaming, the shellcode should be decompiled correctly, and we can begin our static analysis on it.

![alt text](/uploads/diavol10.PNG)

*Figure 10: Fixing Shellcode's API Calls In IDA.*

## Command-line Arguments

**DIAVOL** can run with or without command-line arguments.

Below is the list of arguments that can be supplied by the operator.

| Argument   | Description |
| -------- | ----------- |
|**-p \<target\>**| Path to a file containing files/directories to be encrypt specifically |
|**-h \<target\>**| Path to a file containing remote files/directories to enumerate with SMB |
| **-m local** | Encrypting local files and directories |
| **-m net** | Encrypting network shares |
| **-m scan** | Scanning and encrypting network shares through SMB |
| **-m all** | Encrypting local and network drives without scanning through SMB |
|**-log \<log_filename\>**| Enable logging to the specified log file |
|**-s \<IP_address\>**| Remote server's IP address to register bot |
|**-perc \<percent\>**| Percent of data to be encrypted in a file (default: 10%)|

## Bot ID Generation

The first functionality **DIAVOL** executes is generating the bot ID through loading and executing the shellcode from the resource **GENBOTID**.

Prior to launching the shellcode, **DIAVOL** calls **time64** to retrieve the current timestamp on the system and uses it as the seed for **srand** to initialize the pseudo-random number generator.

Next, it generates the following structure and passes it to the shellcode. The **bot_ID** field is later used to register the victim to the threat actor's remote server, and the **victim_ID** is the victim ID that is written to the ransom note. The **RSA_CRYPT_BUFF** is a buffer that is later used to encrypt files.

``` C
struct DIAVOL_GENBOTID_STRUCT
{
  char* bot_ID;
  wchar_t* victim_ID;
  BYTE* RSA_CRYPT_BUFF;
  int (__stdcall *rand)();
};
```

![alt text](/uploads/new_diavol11.PNG)

*Figure 11: Initialize Structure For GENBOTID.*

To generate the victim ID, the shellcode creates a unique GUID using **CoCreateGuid** and uses it as a random number to index into the string **"0123456789ABCDEF"** to generate a random 32-character string.

![alt text](/uploads/diavol12.PNG)

![alt text](/uploads/diavol13.PNG)

*Figure 12, 13: Generating Random 32-character Victim ID.*

To generate the bot ID, the malware first calls **GetComputerNameA** and **GetUserNameA** to retrieve the computer name and user name. It also calls **RtlGetVersion** to retrieve the version of the victim's computer and uses it to index into the string **"0123456789ABCDEF"** to generate an 8-character string.  

 Then, the bot ID is built in the following string format.

**<computer_name> + <user_name> + "_W" + <8_character_string_from_OS_version> + "."**


![alt text](/uploads/diavol14.PNG)

![alt text](/uploads/diavol15.PNG)

*Figure 14, 15: Generating Bot ID.*

Finally, to populate the **RSA_CRYPT_BUFF** field, the malware calls the **rand** function to generate a random 1024-byte buffer.

![alt text](/uploads/new_diavol16.PNG)

*Figure 16: Generating RSA CRYPT Buffer.*

## Hard-coded Configuration

The configuration of **DIAVOL** is stored in plaintext in memory. To extract it, the malware allocates the following structure using **LocalAlloc** and populates it using the hard-coded values from memory.

``` c
struct DIAVOL_CONFIG
{
  _QWORD server_IP_addr; // remote server to register bot
  wchar_t* group_ID; // bot group ID
  wchar_t* Base64_RSA_key; // Base64-encoded RSA key
  wchar_t* process_kill_list; // processes to kill
  wchar_t* service_stop_list; // services to stop
  wchar_t* file_ignore_list; // filenames to avoid encrypting
  wchar_t* file_include_list; // filenames to include encrypting
  wchar_t* file_wipe_list; // filenames to delete
  wchar_t* target_file_list; // target files to encrypt first (overriden by "-p" command-line)
  wchar_t* ransom_note; // ransom note in reverse
  _QWORD findfiles_complete_flag; // is set to true when the first FINDFILES iteration is done
};
```

![alt text](/uploads/diavol17.PNG)

![alt text](/uploads/diavol18.PNG)

*Figure 17, 18: Populate Configuration.*

Below are the hard-coded values for the configuration.

``` JSON
{
  server_IP_addr: "127.0.0.1",
  group_ID = "c1aaee",
  Base64_RSA_Key = "BgIAAACkAABSU0ExAAQAAAEAAQCxVuiQzWxjl9dwh2F77Jxqt/PIrJoczV2RKluW
M+xv0gSAZrL8DncWw9hif+zsvJq6PcqC0NugL3raLFbaUCUT8KAGgrOkIPmnrQpz
5Ts2pQ0mZ80UlkRpw10CMHgdqChBqsnNkB9XF/CFYo4rndjQG+ZO22WX+EtQr6V8
MYOE1A==",
  process_kill_list = ["iexplore.exe", "msedge.exe", "chrome.exe", "opera.exe", "firefox.exe", "savfmsesp.exe", "zoolz.exe", "firefoxconfig.exe", "tbirdconfig.exe", "thunderbird.exe", "agntsvc.exe", "dbeng50.exe", "dbsnmp.exe", "isqlplussvc.exe", "msaccess.exe", "msftesql.exe", "mydesktopqos.exe", "mydesktopservice.exe", "mysqld-nt.exe", "mysqld-opt.exe", "mysqld.exe", "ocautoupds.exe", "ocssd.exe", "oracle.exe", "sqlagent.exe", "synctime.exe", "thebat.exe", "thebat64.exe", "encsvc.exe", "ocomm.exe", "xfssvccon.exe", "excel.exe", "infopath.exe", "mspub.exe", "onenote.exe", "outlook.exe", "powerpnt.exe", "visio.exe", "wordpad.exe", "CNTAoSMgr.exe", "mbamtray.exe", "NtrtscPccNTMon.exe", "tmlisten.exe", "sqlmangr.exe", "RAgui.exe", "QBCFMonitorService.exe", "supervise.exe", "fdhost.exe", "Culture.exe", "RTVscan.exe", "Defwatch.exe", "wxServerView.exe", "GDscan.exe", "QBW32.exe", "QBDBMgr.exe", "qbupdate.exe", "axlbridge.exe", "360se.exe", "360doctor.exe", "QBIDPService.exe", "wxServer.exe", "httpd.exe", "fdlauncher.exe", "MsDtSrvr.exe", "tomcat6.exe", "java.exe", "wdswfsafe.exe"],
  service_stop_list = ["DefWatch", "ccEvtMgr", "ccSetMgr", "SavRoam", "dbsrv12", "sqlservr", "sqlagent", "Intuit.QuickBooks.FCS", "dbeng8", "QBIDPService", "Culserver", "RTVscan", "vmware-usbarbitator64", "vmware-converter", "VMAuthdService", "VMnetDHCP", "VMUSBArbService", "VMwareHostd", "SQLADHLP", "msmdsrv", "tomcat6", "QBCFMonitorService", "Acronis VSS Provider", "SQL Backups", "SQLsafe Backup Service", "SQLsafe Filter Service", "Symantec System Recovery", "Veeam Backup Catalog Data Service", "Zoolz 2 Service", "AcrSch2Svc", "ARSM", "BackupExecAgentAccelerator", "BackupExecAgentBrowser", "BackupExecDeviceMediaService", "BackupExecJobEngine", "BackupExecManagementService", "BackupExecRPCService", "BackupExecVSSProvider", "bedbg", "MMS", "mozyprobackup", "ntrtscan", "PDVFSService", "SDRSVC", "SNAC", "SQLWriter", "VeeamBackupSvc", "VeeamBrokerSvc", "VeeamCatalogSvc", "VeeamCloudSvc", "VeeamDeploymentService", "VeeamDeploySvc", "VeeamEnterpriseManagerSvc", "VeeamHvIntegrationSvc", "VeeamMountSvc", "VeeamNFSSvc", "VeeamRESTSvc", "VeeamTransportSvc", "sms_site_sql_backup", "MsDtsServer", "MsDtsServer100", "MsDtsServer110", "msftesql$PROD", "MSOLAP$SQL_2008", "MSOLAP$SYSTEM_BGC", "MSOLAP$TPS", "MSOLAP$TPSAMA", "MSSQL$BKUPEXEC", "MSSQL$ECWDB2", "MSSQL$PRACTICEMGT", "MSSQL$PRACTTICEBGC", "MSSQL$PROD", "MSSQL$PROFXENGAGEMENT", "MSSQL$SBSMONITORING", "MSSQL$SHAREPOINT", "MSSQL$SQL_2008", "MSSQL$SQLEXPRESS", "MSSQL$SYSTEM_BGC", "MSSQL$TPS", "MSSQL$TPSAMA", "MSSQL$VEEAMSQL2008R2", "MSSQL$VEEAMSQL2012", "MSSQLFDLauncher", "MSSQLFDLauncher$PROFXENGAGEMENT", "MSSQLFDLauncher$SBSMONITORING", "MSSQLFDLauncher$SHAREPOINT", "MSSQLFDLauncher$SQL_2008", "MSSQLFDLauncher$SYSTEM_BGC", "MSSQLFDLauncher$TPS", "MSSQLFDLauncher$TPSAMA", "MSSQLSERVER", "MSSQLServerADHelper", "MSSQLServerADHelper100", "MSSQLServerOLAPService", "MySQL57", "MySQL80", "OracleClientCache80", "ReportServer$SQL_2008", "RESvc", "SQLAgent$BKUPEXEC", "SQLAgent$CITRIX_METAFRAME", "SQLAgent$CXDB", "SQLAgent$ECWDB2", "SQLAgent$PRACTTICEBGC", "SQLAgent$PRACTTICEMGT", "SQLAgent$PROD", "SQLAgent$PROFXENGAGEMENT", "SQLAgent$SBSMONITORING", "SQLAgent$SHAREPOINT", "SQLAgent$SQL_2008", "SQLAgent$SQLEXPRESS", "SQLAgent$SYSTEM_BGC", "SQLAgent$TPS", "SQLAgent$TPSAMA", "SQLAgent$VEEAMSQL2008R2", "SQLAgent$VEEAMSQL2012", "SQLBrowser", "SQLSafeOLRService", "SQLSERVERAGENT", "SQLTELEMETRY", "SQLTELEMETRY$ECWDB2", "mssql$vim_sqlexp", "IISAdmin", "NetMsmqActivator", "POP3Svc", "SstpSvc", "UI0Detect", "W3Svc", "aphidmonitorservice", "intel(r) proset monitoring service", "unistoresvc_1af40a", "audioendpointbuilder", "MSExchangeES", "MSExchangeIS", "MSExchangeMGMT", "MSExchangeMTA", "MSExchangeSA", "MSExchangeSRS", "msexchangeadtopology", "msexchangeimap4", "Sophos Agent", "Sophos AutoUpdate Service", "Sophos Clean Service", "Sophos Device Control Service", "Sophos File Scanner Service", "Sophos Health Service", "Sophos MCS Agent", "Sophos MCS Client", "Sophos Message Router", "Sophos Safestore Service", "Sophos System Protection Service", "Sophos Web Control Service", "AcronisAgent", "Antivirus", "AVP", "DCAgent", "EhttpSrv", "ekrn", "EPSecurityService", "EPUpdateService", "EsgShKernel", "ESHASRV", "FA_Scheduler", "IMAP4Svc", "KAVFS", "KAVFSGT", "kavfsslp", "klnagent", "macmnsvc", "masvc", "MBAMService", "MBEndpointAgent", "McAfeeEngineService", "McAfeeFramework", "McAfeeFrameworkMcAfeeFramework", "McShield", "McTaskManager", "mfefire", "mfemms", "mfevtp", "MSSQL$SOPHOS", "sacsvr", "SAVAdminService", "SAVService", "SepMasterService", "ShMonitor", "Smcinst", "SmcService", "SntpService", "sophossps", "SQLAgent$SOPHsvcGenericHost", "swi_filter", "swi_service", "swi_update", "swi_update_64", "TmCCSF", "tmlisten", "TrueKey", "TrueKeyScheduler", "TrueKeyServiceHelWRSVC", "vapiendpoint"],
  file_ignore_list = ["*.exe", "*.sys", "*.dll", "*.lock64", "*readme_for_decrypt.txt", "*locker.txt", "*unlocker.txt", "%WINDIR%\\", "%PROGRAMFILES%\\", "%PROGRAMW6432%\\", "*\\Microsoft\\", "*\\Windows\\", "*\\Program Files*\\", "%TEMP%\\"],
  file_include_list = ["*"],
  file_wipe_list = [],
  target_file_list = [],
  ransom_note = "\n\r!NPV revo roT esu ot yrT .krowten etaroproc ro yrtnuoc ruoy ni kcolb eb yam resworB roT\n\r\n\r%tob_dic%/<redacted>/<redacted>//:sptth - etisbew ruo tisiv dna resworB roT eht nepO .2\n\r.ti llatsni dna resworB roT daolnwoD .1\n\r\n\r# ?kcab selif ym teg ot woH #\n\r\n\r.etisbew swen ruo no dehsilbup eb lliw tnemyap gnikam ton fo esac ni taht krowten ruoy morf atad dedaolnwod osla evah ew taht noitaredisnoc otni ekaT\n\r.krowten eht erotser rof loot noitpyrced y"
}
```

## Bot Registration

To register the victim as a bot, **DIAVOL** first builds the content of the POST request to later be sent to the register remote server.

This is done through combining the bot ID generated in [Bot ID Generation](#bot-id-generation) and the hard-coded group ID in the configuration in the following format.

``` CSS
cid=<bot_ID>&group=<group_ID>&ip_local1=111.111.111.111&ip_local2=222.222.222.222&ip_external=2.16.7.12
```

![alt text](/uploads/diavol19.PNG)

*Figure 19: Building Register Request.*

Next, the malware allocates memory for the following structure before loading and executing the shellcode from resource **REGISTER**.

``` c
struct DIAVOL_REGISTER_STRUCT
{
  char* agent; // "Agent"
  char* C2_IP_addr; // C2 IP address from configuration or command-line "-s"
  char* request_type; // "POST"
  char* domain_dir; // "/BnpOnspQwtjCA/register"
  char* content_type; // "Content-Type: application/x-www-form-urlencoded; charset=UTF-8"
  __int64 content_type_len; // length of content type
  char* payload_content; // register request
  __int64 payload_content_len; // length of register request
};
```

![alt text](/uploads/diavol20.PNG)

*Figure 20: Building Register Structure & Register Bot.*

To send the POST request, the shellcode **InternetOpenA** to initializes the application's use of the **WinINet** functions, **InternetConnectA** to connect to the C2 server, **HttpOpenRequestA** to open a POST request at the specified domain directory, and **HttpSendRequestA** to send the crafted POST request.

Finally, the malware calls **HttpQueryInfoA** to query and return the server's response.

![alt text](/uploads/diavol21.PNG)

*Figure 21: Sending POST Request To Register Bot.*

## Configuration Overriding

Beside using the command line parameters, **DIAVOL** can also request different values from its remote server to override the configuration fields unlike most major ransomware.

First, the malware checks to make sure the victim has been properly registered as a bot to the main register server by checking if the server's response code is 200.

![alt text](/uploads/diavol22.PNG)

*Figure 22: Checking Register Response Code.*

Next, it loads and executes the shellcode from the resource **FROMNET** to request different configuration values.

For the calls to the shellcode, the malware allocates the following structure before passing it in as a parameter.

``` C
struct DIAVOL_FROMNET_STRUCT
{
  char* agent; // "Agent"
  char* C2_IP_addr; // "173.232.146.118" (Hard-coded)
  char* request_type; // "GET"
  char* domain_dir; // "/Bnyar8RsK04ug/<bot_ID>/<group_ID>/<field_name>
  char* content_type; // "Content-Type: application/x-www-form-urlencoded; charset=UTF-8"
  __int64 content_type_len; // the length of the content type
};
```

For the domain directory of the server's address, the field name depends on the configuration field the malware is requesting. Once registration is done, **DIAVOL** requests for the following field names:

- **key**: Base64-encoded RSA key
- **services**: service stop list
- **priority**: target files to encrypt first
- **ignore**: filenames to avoid encrypting
- **ext**: filenames to include encrypting
- **wipe**: filenames to delete
- **landing**: Ransom note

![alt text](/uploads/diavol23.PNG)

*Figure 23: Populating FROMNET Structure.*

The shellcode calls **InternetConnectA** to connect to the C2 server, **HttpOpenRequestA** to open a GET request, and **HttpSendRequestA** to send the request. Next, it then calls **InternetReadFile** to read the server's response for the requested field and return that.

![alt text](/uploads/diavol24.PNG)

*Figure 24: Sending GET Request For Config Field.*

Next, because the lists in the configuration contains environment variables, DIAVOL resolves them by calling **GetEnvironmentVariableW** and converts them to lowercase using **CharLowerBuffW**.

![alt text](/uploads/diavol25.PNG)

*Figure 25: Parsing Configuration Lists.*

Finally, the ransom note in the configuration is reversed and the string **"%cid_bot%"** is replaced with the generated victim ID.

![alt text](/uploads/diavol26.PNG)

*Figure 26: Building Final Ransom Note.*

## Stopping Services

**DIAVOL** loads and executes the shellcode from the resource **SERVPROC** to stop the services specified in the configuration.

![alt text](/uploads/diavol27.PNG)

*Figure 27: Loading & Executing SERVPROC.*

Given a list of services to stop, the shellcode iterates through the list and stops them through the service control manager.

It first calls **OpenSCManagerW** to retrieve a service control manager handle with all access, **OpenServiceW** to retrieve a handle to the target service, and **ControlService** to send a control stop code to stop it.

![alt text](/uploads/diavol28.PNG)

*Figure 28: Stopping Target Services.*

## Terminating Processes

**DIAVOL** loads and executes the shellcode from the resource **KILLPR** to terminate the processes specified in the configuration.

![alt text](/uploads/diavol29.PNG)

*Figure 29: Loading & Executing KILLPR.*

The shellcode first calls **CreateToolhelp32Snapshot** to take a snapshot of all processes in the system. Using the snapshot, it iterates through each process using **Process32FirstW** and **Process32NextW**. For each process, its executable name is compared against every name in the configuration's process list to be terminated.

![alt text](/uploads/diavol30.PNG)

![alt text](/uploads/diavol31.PNG)

*Figure 30, 31: Terminating Target Processes.*

## RSA Initialization

Prior to file encryption, **DIAVOL** sets up the cryptography buffers that are later used to encrypt files.

First, it allocates memory for the following structure before loading and executing the shellcode from resource **RSAINIT**.

``` c
struct DIAVOL_RSAINIT_STRUCT
{
  HCRYPTPROV hCryptProv; // Handle to cryptographic service provider
  BYTE* Base64_RSA_key; // Base64-encoded RSA key
  char* container_str; // "MicrosoftCryptoGuard"
  char* provider_str; // "Microsoft Enhanced Cryptographic Provider v1.0"
  BYTE* RSA_CRYPT_BUFF;
  BYTE* RSA_FOOTER;
};
```

![alt text](/uploads/new_diavol32.PNG)

*Figure 32: Loading & Executing RSAINIT.*

The shellcode's job is to populate **RSA_FOOTER** field to later be used during file encryption.

First, it calls **CryptStringToBinaryW** to Base64-decode the RSA public key and **CryptAcquireContextW** to retrieve a handle to the corresponding cryptographic service provider.

![alt text](/uploads/diavol33.PNG)

*Figure 33: Decode RSA Key & Retrieve CSP Handle.*

Next, the malware calls **CryptImportKey** to import the RSA public key and retrieve the key handle. It calls **VirtualAlloc** to allocate a memory buffer and divides the **RSA_CRYPT_BUFF** buffer into 117-byte blocks. For each block, **DIAVOL** appends it into the allocated buffer and calls **CryptEncrypt** to encrypt it using the RSA key handle.

![alt text](/uploads/new_diavol34.PNG)

*Figure 34: Importing RSA Public Key & Encrypting **RSA_CRYPT_BUFF**.*

Finally, the 2304-byte encoded buffer will be copied into the **RSA_FOOTER** buffer. How this and the **RSA_CRYPT_BUFF** buffer are used will later be discussed during [file encryption](#encryption-file-encryption).

![alt text](/uploads/diavol35.PNG)

*Figure 35: Writing Encrypted Content Into RSA_FOOTER.*

## Finding Drives To Encrypt

**DIAVOL** loads and executes the shellcode from the resource **ENMDSKS** to enumerate and find all drives in the system when the encryption mode from the command line is **local**, **net**, **scan**, or **all**.

The shellcode receives the list of files to avoid encrypting and a buffer to contain the name of drives found during enumeration as parameters.

![alt text](/uploads/diavol36.PNG)

*Figure 36: Loading & Executing ENMDSKS.*

The shellcode first calls **GetLogicalDriveStringsW** to retrieve a list of all the drives in the system. For each drive, its name is converted into lowercase and passed into **GetDriveTypeW** as a parameter to retrieve its type.

The drive only gets processed if its type is **DRIVE_REMOTE** or **DRIVE_FIXED** and its name is not in the list of files to avoid.

![alt text](/uploads/diavol37.PNG)

*Figure 37: Enumerating Drives.*

If the drive is valid to be encrypted, its name is appended to the buffer of drives from the shellcode's parameter.

![alt text](/uploads/diavol38.PNG)

*Figure 38: Populating Target Drives List.*

If the drive is a remote drive, the malware calls **WNetGetConnectionW** to retrieve the name of the network resource associated with it.

![alt text](/uploads/diavol39.PNG)

*Figure 39: Finding Network Resource From Drive Name.*

Finally, using the name of the network resource, the malware calls **gethostbyname** to retrieve a **hostent** structure that contains the IP address of the remote host.

Finally, **DIAVOL** adds that IP address to the list of files to avoid encrypting.

![alt text](/uploads/diavol40.PNG)

*Figure 40: Adding Network Resource IP Address To Avoid Enumerating Twice.*

## Scanning Target Network Shares Through SMB

**DIAVOL** has two different shellcode for scanning network shares using SMB in the **SMBFAST** and **SMB** resources.

The **SMBFAST** shellcode is used to scan for network shares from the target host list given by the **"-h"** command-line parameter.

Prior to launching this shellcode, **DIAVOL** allocates memory for this following structure to contain information about network hosts to enumerate for shares.

``` c
struct DIAVOL_SMB_STRUCT
{
  FARPROC GetProcAddress;
  FARPROC memset;
  wchar_t *TARGET_NETWORK_SHARE_LIST; // Target network host names to enumerate for shares (from "-h" command-line)
  DWORD *remote_host_IP_list; // Buffer to receive IP address of network hosts
  __int64 curr_network_share_name[16]; // Buffer to contain currently-processed share name
  _WORD DNS_server_name[260]; // Buffer to receive DNS or NetBIOS name of the remote server
  MIB_IPNETTABLE *IpNetTable;
  MIB_IFROW pIfRow;
  __int64 unk[2];
};
```

The malware also allocates memory for this structure to receive the name of all scanned network resources. Both structures are then passed to the shellcode as parameters.

``` c
struct DIAVOL_SMB_LIST
{
  __int64 length;
  char *SMB_net_share_list;
};
```

![alt text](/uploads/diavol41.PNG)

*Figure 41: Loading & Executing SMBFAST.*

Since the **SMBFAST** shellcode only scans for host names in the given target list, it enumerates through the list and writes each network share name into the **curr_network_share_name** field to be processed.

First, the malware calls **gethostbyname** to retrieve a **hostent** structure for the current share name. Using the structure, it extracts the host's list of IP addresses and appends it to the **remote_host_IP_list** field.

![alt text](/uploads/diavol42.PNG)

*Figure 42: SMBFAST: Retrieve Target Host IP Addresses.*

Next, for each IP address retrieve from the host, the malware writes it to the **DIAVOL_SMB_STRUCT->DNS_server_name** buffer. This is then passed as a parameter to a **NetShareEnum** call to retrieve information about each shared resource on the server with that IP address.

![alt text](/uploads/diavol43.PNG)

*Figure 43: SMBFAST: Retrieve Share Resource Info From IP Address.*

Next, for each resource on the server, **DIAVOL** adds it to the **DIAVOL_SMB_LIST->SMB_net_share_list** buffer in the following format.

``` r
<Server_IP_Address>//<Resource_Name>//
```

The resource name is extracted from the **shi1_netname** from the **SHARE_INFO_1** structure that comes from the previous **NetShareEnum** call.

![alt text](/uploads/diavol44.PNG)

![alt text](/uploads/diavol45.PNG)

*Figure 44, 45: SMBFAST: Adding Share Resource's Full Path To Output List.*

The final list is later used to encrypt these shared resources.

## Scanning Network Shares In ARP Table Through SMB

The **SMB** shellcode is used to scan for network shares from the hosts extracted from the **Address Resolution Protocol (ARP)** table.

Prior to launching this shellcode, **DIAVOL** allocates memory for the **DIAVOL_SMB_STRUCT** structure and the **DIAVOL_SMB_LIST** structure similar to the **SMBFAST** shellcode.

![alt text](/uploads/diavol46.PNG)

*Figure 46: Loading & Executing SMB.*

First, the shellcode calls **GetIpNetTable** to retrieve the IPv4-to-physical address mapping table on the victim's machine.

Using that table, the malware extracts the list of **MIB_IPNETROW** structures containing entries for IP addresses in the ARP table. For each **MIB_IPNETROW** structure, **DIAVOL** calls **GetIfEntry** to retrieve information for the specified interface on the local computer.

![alt text](/uploads/diavol47.PNG)

*Figure 47: SMB: Retrieving Information For IP Addresses In ARP Table.*

Next, the malware iterates through the **DIAVOL_SMB_STRUCT->remote_host_IP_list** buffer to check if any given IP address from the "-h" command-line parameter is in the ARP table.

![alt text](/uploads/diavol48.PNG)

*Figure 48: SMB: Looking Up Target IP Addresses In ARP Table.*

For each target IP address that is also in the ARP table, the malware writes it to the **DIAVOL_SMB_STRUCT->DNS_server_name** buffer. This is then passed as a parameter to a **NetShareEnum** call to retrieve information about each shared resource on the server with that IP address.

![alt text](/uploads/diavol49.PNG)

*Figure 49: SMB: Retrieve Share Resource Info From IP Address.*

The rest of the code is similar to the **SMBFAST** shellcode. For each resource on the server, **DIAVOL** adds it to the **DIAVOL_SMB_LIST->SMB_net_share_list** buffer in the following format.

``` r
<Server_IP_Address>//<Resource_Name>//
```

## Encryption: Target File Enumeration

**DIAVOL's** file encryption is divided into three parts. The first part is enumerating and encrypting all files from the target list in the malware's configuration.

Up to this point, the files and directories in the list can come from the hard-coded values in memory or from the command-line parameter **"-p"**.

First, it allocates memory for the following structure before loading and executing the shellcode from resource **FINDFILES**.

``` c
struct DIAVOL_FINDFILES_STRUCT
{
  char* target_file; // The name of the file/directory to be encrypted
  DIAVOL_CONFIG *diavol_config; // Malware configuration
  FARPROC encrypt_file; // Function to encrypt file
};
```

For the **target_file** field, the malware iterates through the target file list and launches the **FINDFILES** shellcode to encrypt each one.

![alt text](/uploads/diavol50.PNG)

*Figure 50: Loading & Executing FINDFILES.*

The **FINDFILES** shellcode first converts the target filename to lowercase and checks to make sure the filename does not match with anything in the configuration's file to ignore list or the target file list (to avoid enumerating a directory twice).

Because the names in the list can contain wildcard characters (**'*'** for matching zero or more characters and **'?'** for matching one character), the shellcode contains some additional code to check for that against the target filename.

![alt text](/uploads/diavol51.PNG)

*Figure 51: Checking To Avoid Encrypting File.*

Next, **DIAVOL** calls **FindFirstFileW** to begin its enumeration on the target file. For each file it finds, the malware checks and avoids files whose name are **"."** or **".."** to infinite recursion during enumeration.

![alt text](/uploads/diavol52.PNG)

*Figure 52: Starting Enumeration.*

If the currently processed file is a directory, the malware similarly converts it into lowercase and checks to make sure the filename is not in the file to ignore list or the target file list.

If the found directory is valid to be enumerated, the malware updates the **target_file** field to the directory's name and recursively calls the **FINDFILES** shellcode function again.

If it is not valid, **DIAVOL** calls **FindNextFileW** to move on to find another file.

![alt text](/uploads/diavol53.PNG)

*Figure 53: Recursive Traversal On Found Directories.*

If the currently processed file is a directory, the malware also converts it into lowercase and checks to make sure the filename is not in the file to ignore list or the target file list.

If the filename is in the configuration's file to wipe list, the malware calls **DeleteFileW** to delete it.

![alt text](/uploads/diavol54.PNG)

*Figure 54: Deleting File.*

Next, if the filename's format matches with anything in the configuration's file to include list, the malware calls **LocalAlloc** to allocate memory and write the filename in there. Finally, it passes the allocated buffer to the **DIAVOL_FINDFILES_STRUCT->encrypt_file** function to encrypt it.

![alt text](/uploads/diavol55.PNG)

*Figure 55: Sending File To Be Encrypted.*

Once the enumeration is done for the original target file, the malware calls **FindClose** to close the file search handle and pass the target file's name to the **DIAVOL_FINDFILES_STRUCT->encrypt_file** function to encrypt it.

![alt text](/uploads/diavol56.PNG)

*Figure 56: Closing Search Handle & Encrypting Target File.*

The **encrypt_file** function will be analyzed in [a later section](#encryption-file-encryption). This function can either take in a directory name or a filename as the parameter.

## Encryption: Remote File Enumeration Through SMB

After scanning the network for network share resources through the **SMBFAST** and **SMB** shellcodes, the malware spawns threads to enumerate the resources in those lists.

Prior to each **thread_encrypt** call, the malware updates the **target_file** field to contain each resource list from the two shellcodes.

![alt text](/uploads/diavol57.PNG)

*Figure 57: Setting Up Network Resource Enumeration.*

The **thread_encrypt** function calls **CreateThread** to create a suspended thread launching an inner function with the **FINDFILES** structure passed in as parameter.

**DIAVOL** also passes the thread handle to a global handle array to later launch it.

![alt text](/uploads/diavol58.PNG)

*Figure 58: Launching Suspended Thread To Enumerate Share Resource.*

For each resource in the list, the thread executes the **FINDFILES** to enumerate it.

![alt text](/uploads/diavol59.PNG)

*Figure 59: Thread To Launch FINDFILES Shellcode To Enumerate Resource.*

Finally, to launch all these threads to begin the remote file enumeration, the malware iterates through the global handle array and calls **ResumeThread** on each thread handle.

![alt text](/uploads/diavol60.PNG)

*Figure 60: Resuming Suspended Threads To Begin Enumeration.*

## Encryption: System Drives Enumeration

The final part of the enumeration is on the local and network drives retrieved from the **ENMDSKS** shellcode in [the previous section](#finding-drives-to-encrypt).

The list of drives to encrypt is passed to the **target_file** field in the **FINDFILES** structure, and the malware launches the **FINDFILES** shellcode to enumerate and encrypt each drive.

![alt text](/uploads/diavol61.PNG)

*Figure 61: Enumerating & Encrypting Network + Local Drives.*

## Encryption: File Encryption

The **encrypt_file** used in the **FINDFILES** shellcode takes in the name of a directory/file to encrypt.

First, it sets up the following structure.

``` c
struct DIAVOL_ENCDEFILES_TRUCT
{
  HANDLE RSA_hKey; // RSA Public Key Handle
  wchar_t *file_name; // filename to encrypt
  __int64 MAX_FILE_CRYPT_PERCENT; // From the "-perc" command-line parameter
  FARPROC calculate_percent; // function to calculate percent (a / b * c where b is 100)
  BYTE *RSA_CRYPT_BUFF;
  BYTE *RSA_FOOTER;
  FARPROC log_to_file; // logging function
};
```

![alt text](/uploads/new_diavol62.PNG)

*Figure 62: Populating ENCDEFILES Structure.*

If the name from the parameter is a directory, **DIAVOL** calls **SetCurrentDirectoryW** to change the current directory for the malware's process to the directory's name.

It then calls **CreateFileW** to create the ransom note file and **WriteFile** to write the ransom note in there.

![alt text](/uploads/diavol63.PNG)

*Figure 63: Dropping Ransom Note.*

Earlier, before setting up the **FINDFILES** shellcode, the malware also loads the **ENCDEFILE** shellcode into another buffer in memory.

When the name from the parameter is of a file, the malware launches the **ENCDEFILE** shellcode to encrypt it.

![alt text](/uploads/diavol64.PNG)

*Figure 64: Launching ENCDEFILE Shellcode To Encrypt File.*

To encrypt the file, the shellcode first calls **CreateFileW** to retrieve a handle for the target file.

It then calls **GetFileSizeEx** to retrieve the size of the file and calculates the maximum size to encrypt the file. This is done by calculating the **MAX_FILE_CRYPT_PERCENT** percent from the total file size.

Next, the file is encrypted in 2048-byte blocks each, and the malware allocates a 2048-byte buffer using **VirtualAlloc** to host this data. For each block, **DIAVOL** calls **ReadFile** to read data into the allocated buffer and encrypts it using the **RSA_CRYPT_BUFF** buffer.

It then calls **SetFilePointerEx** to set the file pointer to the beginning of the newly encrypted block and calls **WriteFile** to write the encrypted block back in.

After the encryption is finished, **DIAVOL** calls **SetFilePointerEx** to set the file pointer to the end of the file. It then calls **WriteFile** to write to the end the **RSA_FOOTER** buffer, the max file size to encrypt, and the negation of every byte of that size.

Using this file footer, the threat actor's decryptor can retrieve the **RSA_FOOTER** buffer and decrypt it into the **RSA_CRYPT_BUFF** buffer using their RSA private key to decrypt the file.

![alt text](/uploads/diavol66.PNG)

*Figure 66: Writing File Footer.*

Finally, **DIAVOL** calls **VirtualAlloc** to allocate a buffer to store the encrypted filename. It writes the original filename in this buffer and appends it with the extension **".lock64"** before calling **MoveFileW** to change the filename.

![alt text](/uploads/diavol67.PNG)

*Figure 67: Setting Encrypted File Extension.*

## Shadow Copies Deletion

To delete all shadow copies on the system, **DIAVOL** loads and executes the shellcode from the **VSSMOD** resource.

![alt text](/uploads/diavol68.PNG)

*Figure 68: Loading & Executing VSSMOD.*

First, the shellcode resolves these two stackstrings:

- "CompSpec"
- "/c vssadmin Delete Shadows /All /Quiet >> NULL"

![alt text](/uploads/diavol69.PNG)
![alt text](/uploads/diavol70.PNG)

*Figure 69, 70: Resolving Stackstrings.*

Next, it calls **GetEnvironmentVariableW** on the "CompSpec" string to retrieve a full path to the command-line interpreter.

With that, it calls **ShellExecuteW** to execute the command **"vssadmin Delete Shadows /All /Quiet >> NULL"** to delete all shadow copies on the system.

![alt text](/uploads/diavol71.PNG)

*Figure 71: Deleting Shadow Copies.*

## Changing Desktop Image

To change the desktop image, **DIAVOL** loads and executes the shellcode from the **CHNGDESK** resource.

![alt text](/uploads/diavol72.PNG)

*Figure 72: Loading & Executing CHNGDESK.*

The shellcode first resolves the following stackstrings:

- ".\encr.bmp"
- "Control Panel\Desktop"
- "Wallpaper"
- "WallpaperOld"

Next, it calls **RegOpenKeyExW** to retrieve the registry key using the sub key **"Control Panel\Desktop"**. With the registry key, the malware calls **RegQueryValueExW** to query the path to the current wallpaper image and **RegSetValueExW** to set that path as the value of **"WallpaperOld"**.

![alt text](/uploads/diavol73.PNG)

*Figure 73: Setting WallpaperOld Registry Value.*

To build the bitmap path to drop on the system, the malware calls **GetDesktopWindow** and **SHGetSpecialFolderPathW** to retrieve the path to the special folder containing image files common to all users. It then appends **"encr.bmp"** to that path.

![alt text](/uploads/diavol74.PNG)

*Figure 74: Building Bitmap Path.*

To build the bitmap from scratch, **DIAVOL** calls **CreateCompatibleDC**, **GetDesktopWindow**, and **CreateDIBSection** to create a bitmap as big as the current desktop window size. It also calls **GetStockObject** to set the bitmap's background to black and **SetTextColor** to set the text color to white.

![alt text](/uploads/diavol75.PNG)

*Figure 75: Creating Background Bitmap.*

Next, it resolves the following stackstrings:

- "All your files are encrypted!"
- "For more information see README-FOR-DECRYPT.txt"

The malware then calls **DrawTextW** to write these two strings into the bitmap, **CreateFileW** to create the bitmap file in the special folder, and **WriteFile** to write the generated bitmap into the file.

![alt text](/uploads/diavol76.PNG)

*Figure 76: Writing Bitmap Data To File.*

Finally, it calls **SystemParametersInfoW** to set wallpaper to the newly created bitmap file. 

![alt text](/uploads/diavol77.PNG)

*Figure 77: Setting Wallpaper To Generated Bitmap.*

## Self Deletion

After finishing file encryption and changing the wallpaper, the malware deletes its own executable.

First, it calls **GetModuleFileNameW** to retrieve its own executable path. Then it builds the following string using that.

``` r
"/c del <malware_executable_path> >> NULL"
```

![alt text](/uploads/diavol78.PNG)

*Figure 78: Building CMD Parameter.*

Next, it calls **GetEnvironmentVariableW** on the "CompSpec" string to retrieve a full path to the command-line interpreter.

With that, it calls **ShellExecuteW** to execute the parameter above to delete its own executable.

![alt text](/uploads/diavol79.PNG)

*Figure 79: Deleting Its Own Executable.*

## Logging

Throughout its execution, **DIAVOL** logs all of its operations when logging is enabled through command-line.

In the logging function, the malware receives a string as a parameter. It calls **GetLocalTime** to retrieve the current system time when the logging occurs and write that to the log file buffer.

The malware then appends the input string parameter to the log file buffer and calls **WriteFile** to write to the log file.

![alt text](/uploads/diavol80.PNG)

*Figure 80: Logging Functionality.*

## References

https://www.fortinet.com/blog/threat-research/diavol-new-ransomware-used-by-wizard-spider

https://securityintelligence.com/posts/analysis-of-diavol-ransomware-link-trickbot-gang/

yashechka, don't be too distanced ;) Just wanna say hi on XSS
