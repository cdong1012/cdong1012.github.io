---
title: RegretLocker
categories:
  - Reverse Engineering
description: Malware Analysis Report - RegretLocker
---

# RegretLocker


## Summary


***RegretLocker*** is a new ransomware that has been found in the wild in the last month that does not only encrypt normal files on disk like other ransomwares. When running, it will particularly search for ***VHD*** files, mount them using ***Windows Virtual Storage API***, and then encrypt all the files it finds inside of those ***VHD*** files.


Typically, ***VHD*** files are huge in size with a max size of nearly 2TB because it's mainly ussed to store the contents of a hard disk of a VM which includes disk particitions and file systems. This makes it unrealistic for ransomware to waste time encrypting simply because it's too big.


However, through mounting these virtual disks as physical disks, ***RegretLocker*** can go through and encrypt the individual files inside, which significantly increases encryption speed overall.


For encryption, ***RegretLocker*** reaches out to the C&C server for a ***RSA*** key in order to encrypt and produce a unique ***AES*** key. This ***AES*** key will be used to encrypt all of the files on the disks. However, if the machine is offline or it can't reach C&C, it will just uses the hard-coded ***RSA*** key in memory, which makes it simple to write a decryption tool for!


All of the encrypted files have the extension ***.mouse***.


Huge shout-outs to [Vitali Kremez](https://twitter.com/VK_Intel) and [MalwareHunterTeam](https://twitter.com/malwrhunterteam) for bringing this ransomware to my attention!

![alt text](/uploads/RegretLocker.png)

## IOCS

***RegretLocker*** comes in the form of a 32-bit PE file.

***MD5***: 3265b2b0afc6d2ad0bdd55af8edb9b37

***SHA256***: a188e147ba147455ce5e3a6eb8ac1a46bdd58588de7af53d4ad542c6986491f4

![alt text](/uploads/VT_result.PNG)


## Dependencies

***Advapi32.dll and Crypt32.dll***: Main crypto functionalities such as RSA and AES encryption

***VirtDisk.dll***: Mounting virtual disk functionalities

***tor-lib.dll***: DLL dropped by ***RegretLocker*** that is used to contact C&C through Tor


## Networking

***RegretLocker*** contacts the C&C server at ***http://regretzjibibtcgb.onion/input*** through Tor 3 times:

    - Retrieve RSA key from server
    - Sending information such as the computer's IP, name, volume of the disks,..
    - Signalling when it finishes encrypting


Before contacting C&C, it sends a GET request to ***http://api.ipify.org/*** to retrieve the PC's public IP address. If this fails, the malware can assume that it's running offline and will use the hard-coded RSA key.

## Ransom Note


***RegretLocker*** drops a ransom note in every folder that it encrypts. This is the content if you run the malware with Internet connection. The hash is used to identify which RSA key is used to generate the AES key on your machine.


![alt text](/uploads/RegretLockerRansomnote.PNG)


You can find malware log [here](/uploads/locker.log) on my Github 


## Code Analysis


### Only One Process Running


***RegretLocker*** first check if there is only one version of itself running by looping through all of the running processes using ***CreateToolhelp32Snapshot, Process32First, and Process32Next***. 


For each of the running processes, it compares the name against its own name to make sure that there is no process with the same name. 


If there is one with the same name, the ransomware exits immediately.


![alt text](/uploads/RegretLocker1.png)


### Dropping tor-lib.dll


The malware extracts the path to the current directory it is located in through ***GetModuleFileNameA*** and concats ***"\\tor-lib.dll"*** to it, which means that it drops this dll in the same directory of the malware.


![alt text](/uploads/RegretLocker2.png)


It then calls a function to extract the dll from its resource section through ***FindResourceA, LoadResource, and LockResource***. As we can see in ***Resource Hacker***, the dll is stored unencrypted in the resource section. After extracting the dll, it calls ***LoadLibrary*** to get a handle to the dll. This handle will be used for the malware to contact C&C.


![alt text](/uploads/RegretLocker3.png)


### Development Check


The malware writter has 2 weird checks to check for a particular user name and PC name(***WIN-295748OMAKG***). If the user name or the PC name matches, the malware will exit immediately.


This is potentially just a check against the development PC to make sure that the ransomware does not try to encrypt the machine during development.


As a developer myself, I'm disappointed by this unprofessionalism :disappointed:. Clean up your damn code please!


![alt text](/uploads/RegretLocker4.png)

### Persistence


For persistence, the malware set the registry ***SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*** to the path of the malware. This ensures that the malware is automatically run every time the user logs into the machine.


![alt text](/uploads/RegretLocker5.png)


Next, it also schedules the malware as a task every minite using this ***Schtasks.exe*** command, which is run from ***cmd.exe*** using ***ShellExecuteA***.

```
  schtasks /Create /SC MINUTE /TN "Mouse Application" /TR "RegretLocker_path" /f
```

![alt text](/uploads/RegretLocker6.png)


### Encryption Setup

The malware builds and executes this command from ***cmd.exe***.

```
  cmd.exe /C wmic SHADOWCOPY DELETE & wbadmin DELETE SYSTEMSTATEBACKUP & bcdedit.exe / set{ default } bootstatuspolicy ignoreallfailures & bcdedit.exe / set{ default } recoveryenabled No
```

  - ***wmic SHADOWCOPY DELETE***: This will delete all of the shadow copies of the files on the system, preventing the encrypted files to be reverted to their previous state.
  - ***wbadmin DELETE SYSTEMSTATEBACKUP***: Delete system backup. Preventing the system to go back to a previous snapshot
  - ***bcdedit.exe / set{ default } bootstatuspolicy ignoreallfailures***: Set the boot status policy to ignore errors during a failed boot. Make sure the PC does not fail over to Windows recovery or reboot.
  - ***bcdedit.exe / set{ default } recoveryenabled No***: Make sure the system can't be recovered.


Next, it loops through all the drives and add the name of those with the drive type ***DRIVE_FIXED, DRIVE_REMOVABLE, or DRIVE_REMOTE***.


![alt text](/uploads/RegretLocker7.png)


These names are mounted to the C drive using ***GetVolumePathNamesForVolumeNameA, SetVolumeMountPointA, FindFirstVolumeA, and FindNextVolumeA***. Since this function name is labeled as *show_hided_drives()*, this function just probably mounts all the valid drives so it won't miss any hidden drive.


![alt text](/uploads/RegretLocker8.png)


### Retrieving RSA key


As discussed above, the malware will first reach out to C&C at ***http://regretzjibibtcgb.onion/input*** with ***get_key*** in the query to request the RSA key.


![alt text](/uploads/RegretLocker9.png)


The global variable ***RSA_KEY*** will be written accordingly with the RSA key depending on if it can reach the C&C or not. If it can't, it will use this hard-coded RSA key.

```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1ZQInrnhxXCtAN/LsOX2GmgbvBxMsO49lc1/qodshkUvRQLazWv61UbMLKx2gaRQrCYuVrR1Cgd7LxY4ueGo50TqZioAJbCcfzdiXlEkJqLlz4RTU9RFZ/wFjWxChek2NsU6vLLSowPPTw+JhwTooI+QPAIYeoxCf4xz7Kvu9CQIDAQAB
-----END PUBLIC KEY-----
```

### Generating AES key


Using the RSA key, it will call ***CryptAcquireContextA, CryptDecodeObjectEx, CryptImportPublicKeyInfo, and CryptEncrypt*** to encrypt the "AES" buffer in memory, generating a new AES key


![alt text](/uploads/RegretLocker14.png)


With this method, the malware can generate a different AES key as long as it's receiving a different RSA key from C&C. However, this AES key is constant after this encryption if the malware is run offline, so it should be straightforward to produce a decrypting tool if either C&C is down or the PC is not connected to the Internet.


### Encryption - USB Drives

The first encryption happens to USB drives, if there are any. This function is called to retrieve the name of all the USB drives by checking for any drive with ***DRIVE_REMOVABLE*** type.
This function was pretty similar of the one previously used in *show_hided_drives()*.


![alt text](/uploads/RegretLocker10.png)


Next, it loops through all of these USB drives and call a function to encrypt its content. I label this as *small_encrypt()* because it is used to encrypt USB drives and small files only.


![alt text](/uploads/RegretLocker11.png)


I will dive into these encryption functions later because there are a few different version to cover.


### Encryption - SMB Scanner 

The malware is written in C++, and there is a class called ***smb_scanner***. The SMB function tries SMB scanning to find 
  - Adapter names and address ranges on the adapter
  - NetServers's IP addresses and machine names on the server using ***NetServerEnum***.


![alt text](/uploads/RegretLocker12.png)


The result value is a buffer of all the SMB folders in string form.

Then, it goes through a while loop calling a function to encrypt these SMB folders, so I label this encryption function as *smb_encrypt()*. I actually have not set up SMB on my virtual machine, so when I ran this, I did not know if it could actually encrypt SMB folders or not...


![alt text](/uploads/RegretLocker13.png)



### Encryption - Large Files


The malware has a specific method of looking for large files and then begins to encrypt them right after the SMB encryption.


![alt text](/uploads/RegretLocker15.png)


The malware author called this encryting function *encrypt_large_file()*, so I just went along with it. Seems like it's the same as most of the other encrypting functions except that it has extra stuff to account for the file size. The core of this function still boils down to an AES encryption.

![alt text](/uploads/RegretLocker16.png)


After the encryption, it will rename the encrypted file to the same name but with the extension ***.mouse*** and overwrite the file buffer with this newly encrypted buffer.


### Encryption - Everything Else


After the large file encryption, ***RegretLocker*** goes into a while loop to encrypt everything else with *small_encrypt()*.


![alt text](/uploads/RegretLocker17.PNG)


*small_encrypt()* calls a wrapper function to navigate around directories and files before encrypting them. It specifically looks out for these to avoid encrypting them.

  - ***RegretLocker file***
  - ***.log***
  - ***HOW TO RESTORE FILES.TXT***
  - ***Windows folder***
  - ***ProgramData***
  - ***Microsoft***
  - ***System***


Next, it checks the file type. If the file type is FILE_ATTRIBUTE_DIRECTORY, it will calls a recursive encrypting function to recursively go through every layer inside the folder. If the file type is not a folder, it will simply call the main encrypting function to encrypt it.


![alt text](/uploads/RegretLocker18.png)


Inside of the recursive encrypting function, ***RegretLocker*** specifically looks for these file names to avoid encrypting them.

  - ***Cheat***
  - ***Notepad***
  - ***x96dbg***
  - ***Hex Editor***
  - ***tor-lib.dll***
  - ***.mouse***


Since the drives are mounted, ***RegretLocker*** checks the file extension for ***".vhd"*** in order to detect any virtual drive. If found, it will call a function to open the virtual drive to start encrypting everything inside by recursively calling back to the recursive function. The ransomware uses a series of calls to ***OpenVirtualDisk, AttachVirtualDisk, GetVirtualDiskPhysicalPath, FindFirstVolumeW, CreateFileW, DeviceIoControl, GetVolumePathNamesForVolumeNameW, and FindNextVolumeW*** to retrieve a list of file and folder names inside.


![alt text](/uploads/RegretLocker19.png)


If the file is not a folder, it will just call the main encrypting function to encrypt it.


This function is divided into 2 condition blocks. If the file size is greater than 104857600 bytes or around 105MB, the file is counted as a large file and will be encrypted with the *encrypt_large_file()* function. If it's not, then ***RegretLocker*** proceeds to encrypt it using AES.


![alt text](/uploads/RegretLocker20.PNG)


There is a catch here. If the encryption fails, it means the file is running or used by some process. For that case, ***RegretLocker*** will find the process that is currently using this file and attempt to terminate it. It's accomplishing this through the use of ***Restart Manager*** with these API calls.

  - ***RmStartSession***: Start a new session for ***Restart Manager***
  - ***RmRegisterResources***: Registering the file to be encrypted as a resource 
  - ***RmGetList***: Get the list of application of services/processes that are using this resource
  - ***CreateToolhelp32Snapshot, Process32FirstW, and Process32NextW***: Check all running processes for their ID, comparing with the processes above

![alt text](/uploads/RegretLocker21.PNG)


After getting the processes that are using the file, it checks for the name. If they match any of these, they will not be added to the list and closed later.

  - ***vnc***
  - ***ssh***
  - ***mstsc***
  - ***System***
  - ***svchost.exe***

![alt text](/uploads/RegretLocker22.png)


***RegretLocker*** then builds the command string ``` taskkill /F /IM \process_name ``` and runs it with ***cmd.exe***. This command basically just filters out the process with the given process name and terminates it.

The ransomware will continuously loop until it successfully closes the process. Then it will attempt the encryption again.


### Encryption - AES


The core of the encrypting functions above are this one AES encrypting function. It basically just uses the generated AES key to encrypt the file with a series of calls to ***CryptAcquireContextA, CryptImportKey, CryptSetKeyParam, and CryptEncrypt***, which is fairly standard. 


After the encryption, it will write this encrypted buffer back into the file with the new file extension ***.mouse***. It will also check the folder path to see if it has created the file ***HOW TO RESTORE FILES.TXT*** already and created one if it has not.


![alt text](/uploads/RegretLocker23.PNG)


## YARA rule

``` 
rule regretlocker {
	meta:
		description = "YARA rule for RegretLocker"
		reference = "http://chuongdong.com/reverse%20engineering/2020/11/17/RegretLocker/"
		author = "@cPeterr"
		tlp = "white"
	strings:
		$str1 = "tor-lib.dll"
		$str2 = "http://regretzjibibtcgb.onion/input"
		$str3 = ".mouse"
		$cmd1 = "taskkill /F /IM \\"
		$cmd2 = "wmic SHADOWCOPY DELETE"
		$cmd3 = "wbadmin DELETE SYSTEMSTATEBACKUP"
		$cmd4 = "bcdedit.exe / set{ default } bootstatuspolicy ignoreallfailures"
		$cmd5 = "bcdedit.exe / set{ default } recoveryenabled No"
		$func1 = "open_virtual_drive()"
		$func2 = "smb_scanner()"
		$checklarge = { 81 fe 00 00 40 06 }
	condition:
		all of ($str*) and any of ($cmd*) and any of ($func*) and $checklarge
}
```

## Samples

I got my samples from [Any.Run](https://app.any.run/tasks/e19eff7c-6d0f-4b09-95da-23f6ab465bb1/) and [tutorialjinni.com](https://www.tutorialjinni.com/regretlocker-ransomware-sample-download.html)!


## References

https://twitter.com/VK_Intel/status/1323693700371914753
https://twitter.com/malwrhunterteam/status/1321375502179905536
https://github.com/vxunderground/VXUG-Papers/blob/main/Weaponizing%20Windows%20Virtualization/WeaponizingWindowsVirtualization.pdf
