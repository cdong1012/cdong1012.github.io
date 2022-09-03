---
title: PLAY Ransomware
categories:
  - Reverse Engineering
description: Malware Analysis Report - PLAY Ransomware
---

# PLAY Ransomware

## Contents

- [PLAY Ransomware](#play-ransomware)
  - [Contents](#contents)
  - [PLAY CTI](#play-cti)
  - [Overview](#overview)
  - [IOCS](#iocs)
  - [Ransom Note](#ransom-note)
  - [Anti Analysis](#anti-analysis)
    - [Anti-Analysis: Return-Oriented Programming](#anti-analysis-return-oriented-programming)
    - [Anti-Analysis: Garbage Code](#anti-analysis-garbage-code)
    - [Anti-Analysis: API Hashing](#anti-analysis-api-hashing)
    - [Anti-Analysis: String Encryption](#anti-analysis-string-encryption)
  - [Static Code Analysis](#static-code-analysis)
    - [Command-Line Arguments](#command-line-arguments)
    - [Crypto Initialization](#crypto-initialization)
    - [Check Existing Drives](#check-existing-drives)
    - [Recursive Traversal](#recursive-traversal)
    - [Populating File Structure](#populating-file-structure)
    - [Child Thread Encryption](#child-thread-encryption)
    - [File Encryption](#file-encryption)
  - [References](#references)

## PLAY CTI

**PLAY** Ransomware (aka PlayCrypt) campaigns have been active since at least mid-July 2022. Up to five ransom notes of **PLAY** Ransomware have been uploaded to VirusTotal so far. In mid-August 2022, the first public case of **PLAY** Ransomware was announced when a journalist uncovered that Argentina's Judiciary of Córdoba was victimized.

The operators have been known to use common big game hunting (BGH) tactics, such as SystemBC RAT for persistence and Cobalt Strike for post-compromise tactics. They have also been known to use custom PowerShell scripts and AdFind for enumeration, WinPEAS for privilege escalation, and RDP or SMB for lateral movement while inside a target network.

The group appends ".play" to encrypted files and its ransom note only includes the word "PLAY" and an email address to communicate with the threat actors. The threat actors have been known to exfiltrate files using WinSCP but are not known to have a Tor data leak site like many other BGH ransomware campaigns.

Huge thanks to my man [Will Thomas](https://twitter.com/BushidoToken) for this information!

## Overview

This is my analysis for **PLAY Ransomware**. I'll be solely focusing on its anti-analysis and encryption features. There are a few other features such as DLL injection and networking that will not be covered in this analysis.

Despite its simplicity, **PLAY** is heavily obfuscated with a lot of unique tricks that have not been used by any ransomware that comes before.

The malware uses the generic RSA-AES hybrid-cryptosystem to encrypt files. **PLAY's** execution speed is pretty average since it uses a depth-first traversal algorithm to iterate through the file system. Despite launching a separate thread to encrypt each file, this recursive traversal hinders its performance significantly.

## IOCS

The analyzed sample is a 32-bit Windows executable.

**MD5**: 223eff1610b432a1f1aa06c60bd7b9a6

**SHA256**: 006ae41910887f0811a3ba2868ef9576bbd265216554850112319af878f06e55

**Sample**: [MalwareBazaar](https://bazaar.abuse.ch/sample/006ae41910887f0811a3ba2868ef9576bbd265216554850112319af878f06e55/)

![alt text](/uploads/PLAY01.PNG)

*Figure 2: VirusTotal Result.*

## Ransom Note

The content of the default ransom note is stored as an encoded string in **PLAY's** executable, which contains the string *"PLAY"* as well as an email address for the victim to contact the threat actor.

**PLAY's** ransom note filename is **"ReadMe.txt"**.

![alt text](/uploads/PLAY02.PNG)

*Figure 3: ROOK's Ransom Note.*

## Anti Analysis

### Anti-Analysis: Return-Oriented Programming

Upon opening the executable in IDA, we can see that most of the assembly code does not make sense and is not too meaningful. An example can be seen from **WinMain**, where there is no clear return statement with garbage bytes popping up among valid code.

![alt text](/uploads/PLAY03.PNG)

*Figure 3: Anti-decompiling Feature in WinMain.*

As shown in the disassembled code above, the control flow in **WinMain** calls **sub_4142F5**, and upon return, **edi** is popped and we run into the garbage bytes at 0x4142F2. As a result, IDA fails to decompile this code properly.

![alt text](/uploads/PLAY04.PNG)

*Figure 4: Unpatched WinMain Decompiled Code.*

Examine **sub_4142F5**, we see that the value stored at the stack pointer is immediately added by 0x35 before a **retn** instruction is executed.

We know that the **call** instruction basically contains two atomic instructions, one pushing the address of the next instruction (after the **call** instruction) onto the stack and one jumping to the subroutine being called. When the code enter **sub_4142F5**, the return address (in this case, it is 0x4142F1) is stored at the stack pointer on top of the stack. The subroutine adds 0x35 to this, changing the return address to 0x414326, and **retn** to jump to it.

Knowing this, we can scroll down and try to disassembly the bytes at 0x414326 to get the next part of the **WinMain** code.

![alt text](/uploads/PLAY05.PNG)

*Figure 5: Disassembled Hidden Code.*

Using this return-oriented programming approach to divert the regular control flow of the program, **PLAY** is able to bypass most static analysis through IDA's disassembly and decompilation.

We can also quickly see that at 0x41433A, there is another **call** instruction followed by some garbage bytes. This means that the obfuscation occurs multiple times in the code.

My approached to this was to programmatically patch all these **call** instructions up. A simple patch used in my analysis is calculating the jump (the value added to the return address) and replacing the **call** instruction with a **jump** instruction to the target address.

To scan for all of this obfuscated code, I use 3 different (but quite similar) regexes(is this a word?) in IDAPython to find and patch them. You can find my patching script [here](https://github.com/cdong1012/IDAPython-Malware-Scripts/blob/master/PLAY/script.py).

After patching, the **WinMain** code looks something like this.

![alt text](/uploads/PLAY06.PNG)

*Figure 6: Patched WinMain.*

A little underwhelming, but now we have successfully deobfuscated the code, get a meaningful **call** instruction to **sub_415110** and a proper returning statement in the decompiled code!

### Anti-Analysis: Garbage Code

Beside control flow obfuscation, **PLAY** also litters its code with random moving instructions that don't contribute to the main functionality of the program.

![alt text](/uploads/PLAY07.PNG)

![alt text](/uploads/PLAY08.PNG)

*Figure 7, 8: Garbage Code.*

This makes the decompiled code looks a lot messier, and it is not simple to patch all of these ups since valid code is usually stuffed in between of these garbage code. Patching by jumping over them would sometime break the program itself.

The only solution I have for this is to mentally ignore them while analyzing.

### Anti-Analysis: API Hashing

Similar to most modern ransomware, **PLAY** obfuscates its API call through API name hashing. The API resolving function takes in a target hash and a DLL address.

It walks the DLL's export table to get the name of the exports. For each API name, the malware calls **sub_40F580** with the name as the parameter and adds 0x4E986790 to the result to form the final hash. This hash is compared with the target hash, and if they match, the address of the API is returned.

![alt text](/uploads/PLAY09.PNG)

*Figure 9: API Hashing.*

As shown below, the hashing function contains a lot of unique constants, which allows us to quickly look up that it is **xxHash32**. With this, we know that the full hashing algorithm is **xxHash32** with the seed of 1 and the result added to 0x4E986790.

![alt text](/uploads/PLAY10.PNG)

*Figure 10: xxHash32 Code.*

From here, I developed an IDAPython script to automatically resolve all APIs that the malware uses, which you can find [here](https://github.com/cdong1012/IDAPython-Malware-Scripts/blob/master/PLAY/API_resolve.py).

![alt text](/uploads/PLAY11.PNG)

*Figure 11: Resolving APIs.*

### Anti-Analysis: String Encryption

Most important strings in **PLAY** are encoded in memory. The decoding algorithm does not seem to be too clear, so I just dynamic-ed my way through these. School is whooping my ass right now, so I try to avoid analyzing stuff whenever I can.

![alt text](/uploads/PLAY12.PNG)

*Figure 12: PLAY's String Decryption.*

## Static Code Analysis

### Command-Line Arguments

**PLAY** can run with or without command-line arguments.

Below is the list of arguments that can be supplied by the operator.

| Argument                                                   | Description                                                     |
| ---------------------------------------------------------- | --------------------------------------------------------------- |
| **-mc**                                                    | Execute normal functionality. Same as no command-line argument. |
| **-d \<drive path\>**                                      | Encrypt a specific drive                                        |
| **-ip \<shared resource path\> \<username\> \<password\>** | Encrypt network shared resource                                 |
| **-d \<path\>**                                            | Encrypt a specific folder/file                                  |

![alt text](/uploads/PLAY13.PNG)

*Figure 13: Checking Command-Line Arguments.*

### Crypto Initialization

Prior to encryption, **PLAY** initializes and retrieves cryptographic algorithm providers.

First, it calls **BCryptOpenAlgorithmProvider** to load and initialize a CNG provider for random number generation and **BCryptImportKeyPair** to import its hard-coded RSA public key.

![alt text](/uploads/PLAY14.PNG)

*Figure 14: Initializing & Importing Cryptographic Key.*

Next, the malware calls **VirtualAlloc** to allocate a buffer to store 128 file structures used for encrypting files. The structure's size is 0x48 bytes with its content listed below.

``` c
  struct play_file_struct
  {
    int struct_index;
    char *filename;
    int initialized_flag;
    int padding1;
    char *file_path;
    int file_marker[2];
    int chunk_count;
    int chaining_mode_flag;
    DWORD large_file_flag;
    HANDLE AES_provider_handle;
    HANDLE bcrypt_RNG_provider;
    HANDLE RSA_pub_key_handle;
    HANDLE file_handle;
    LARGE_INTEGER file_size;
    DWORD file_data_buffer;
    DWORD padding2;
  };
```

| Field                   | Description                                                                   |
| ----------------------- | ----------------------------------------------------------------------------- |
| **struct_index**        | Index of the structure in the global structure list                           |
| **filename**            | The name of the file being processed                                          |
| **initialized_flag**    | Set to 1 when the structure is populated with a file to encrypt               |
| **file_path**           | Path of the file being processed                                              |
| **file_marker**         | Address of constants to write to file footer marking that it's been encrypted |
| **chunk_count**         | Number of chunks to encrypt in the file                                       |
| **chaining_mode_flag**  | Set to 1 to use chaining mode GCM, 0 to use chaining mode CBC                 |
| **large_file_flag**     | Set to 1 when the processed file is large                                     |
| **AES_provider_handle** | AES algorithm provider handle                                                 |
| **bcrypt_RNG_provider** | RNG algorithm provider handle                                                 |
| **RSA_pub_key_handle**  | RSA public key handle                                                         |
| **file_handle**         | File handle                                                                   |
| **file_size**           | File size                                                                     |
| **file_data_buffer**    | Address to virtual buffer to read file data in                                |

**PLAY** iterates through this global structure list and populates each structure's field. First, it sets the encrypted file markers in the struct to the following hard-coded values, which will later be written to the end of each encrypted file.

![alt text](/uploads/PLAY15.PNG)

*Figure 15: Encrypted File Markers.*

Then, the malware sets the RNG and AES provider handles as well as the RSA public key handle to the structure. These will later be used to generate random AES key and IV to encrypt files. 

![alt text](/uploads/PLAY16.PNG)

*Figure 16: Encrypted File Markers.*

### Check Existing Drives

Before iterating through all drives to encrypt, **PLAY** enumerates all volumes on the victim's system by calling **FindFirstVolumeW** and **FindNextVolumeW**. If the volume is not a CD-ROM drive or a RAM disk, the malware calls **GetVolumePathNamesForVolumeNameW** to retrieve a list of drive letters and mounted folder paths for the specified volume.

If this list is empty, which means the volume is not mounted to any folder, **PLAY** calls **GetDiskFreeSpaceExW** to check if the volume's free space is greater than 0x40000000 bytes. If it is, the malware calls **SetVolumeMountPointW** to try mounting the volume to a drive path.

![alt text](/uploads/PLAY17.PNG)

*Figure 17: Enumerating Volumes.*

For each volume to be mounted, **PLAY** iterates through all characters to find a drive name that it can call **SetVolumeMountPointW** to mount the volume to.

![alt text](/uploads/PLAY18.PNG)

*Figure 18: Setting Mount Point for Volume.*

Using the same trick to iterates through all possible drive names, **PLAY** calls **GetDriveTypeW** to check the type of each drive.

It avoids encrypting CD-ROM drive or RAM disk. If it's a remote drive, the malware calls **WNetGetUniversalNameW** to retrieve the universal name of the network drive.

![alt text](/uploads/PLAY19.PNG)

*Figure 19: Processing Network Drive.*

The final drive path to be encrypted is set to the network drive's universal name or connection name, depending on which exists.

![alt text](/uploads/PLAY20.PNG)

*Figure 20: Retrieving Network Drive Name.*

If the drive is a regular drive, its name remains the same. Each valid drive has its name added to the list of drive names to be traversed and encrypted.

### Recursive Traversal

To begin traversing drives, **PLAY** iterates through the list of drive names above and spawns a thread with **CreateThread** to traverse each drive on the system.

![alt text](/uploads/PLAY21.PNG)

*Figure 21: Spawning Threads to Traverse Drives.*

Before processing a drive, the malware extracts the following ransom note content before dropping it into the drive folder. This is the only place where the ransom note is dropped instead of in every folder like other ransomware.

```
PLAY
teilightomemaucd@gmx.com
```

![alt text](/uploads/PLAY22.PNG)

![alt text](/uploads/PLAY23.PNG)
*Figure 22, 23: Dropping Ransom Note in Drive.*

To begin enumerating, the malware calls **FindFirstFileW** and **FindNextFileW** to enumerate subfolders and files. It specifically checks to avoid processing the current and parent directory paths **"."** and **".."**.

![alt text](/uploads/PLAY24.PNG)
*Figure 24: Enumerating Files.*

If the file encountered is a directory, the malware checks to avoid encrypting the **"Windows"** directory. After that, it concatenates the subdirectory's name to the current file find path and recursively traverse through the subdirectory by calling the traversal function on it.

![alt text](/uploads/PLAY25.PNG)
*Figure 25: Recursively Traverse Subdirectory.*

If the file encountered is a regular file, the malware checks its name as well as its size to see if it's valid for being encrypted.

![alt text](/uploads/PLAY26.PNG)
*Figure 26: Checking Files.*

If its name/extension is in the list below or if its size is less than 6, **PLAY** avoids encrypting it.

```
.exe, .dll, .lnk, .sys, readme.txt, bootmgr, .msi, .PLAY, ReadMe.txt
```

![alt text](/uploads/PLAY27.PNG)

*Figure 27: Checking Filename & Extension.*

**PLAY** also performs an additional check to see if the file extension is that of typical large files to determine its encryption type later. The file is classified as large if its extension is in the list below.

```
mdf, ndf, ldf, frm
```

### Populating File Structure

For each file to be encrypted, **PLAY** first populates the file structure with the appropriate data about the file.

First, it starts iterating through the global file structure list to check if there is an available structure to process the file.

![alt text](/uploads/PLAY28.PNG)

*Figure 28: Checking for Available File Structure.*

If there is no available structure in the global list, **PLAY** calls **Sleep** to have the thread sleep and rechecks until it finds one.

Once the structure is found, the malware sets its **initialized_flag** field to 1 and the **filename** field to the target filename. It also populates other fields such as the file size, large file flag, and file handle.

![alt text](/uploads/PLAY29.PNG)

![alt text](/uploads/PLAY30.PNG)

*Figure 29, 30: Populating A File Structure To Encrypt File.*

### Child Thread Encryption

After populating a file structure for a specific file, **PLAY** spawns a thread to begin encrypting a file.

If the file is not classified as a large file, the malware calculates how many chunks it needs to encrypt depending on the file size. The number of encrypted chunks is 2 if the file size is less than or equal to 0x3fffffff bytes, 3 if the file size is less than or equal to 0x27fffffff bytes and greater than 0x3fffffff bytes, and 0 if the file size is equal to 0x280000000. If the file size is greater than 0x280000000 bytes, then the number of encrypted chunks is 5.

![alt text](/uploads/PLAY31.PNG)

![alt text](/uploads/PLAY32.PNG)

*Figure 32: Calculating Encrypted Chunks.*

The default chaining mode is set to AES-GCM. However, if the file size is greater than 4025 times the encrypted size (which is the chunk size 0x100000 multiplied by the chunk count), the chaining mode is set to AES-CBC. 

This is because AES-GCM has worst performance compared to AES-CBC. According to this [post](https://helpdesk.privateinternetaccess.com/kb/articles/what-s-the-difference-between-aes-cbc-and-aes-gcm#:~:text=AES%2DGCM%20is%20a%20more,mathematics%20involved%20requiring%20serial%20encryption.), AES-GCM is a more secure cipher than AES-CBC, because AES-CBC, operates by XOR'ing (eXclusive OR) each block with the previous block and cannot be written in parallel. This affects performance due to the complex mathematics involved requiring serial encryption.

For file encryption, **PLAY** now introduces a new structure that represents the file footer content that gets written at each encrypted file.

It took me an eternity to fully understand and resolve this structure's fields, which reminds me I'm probably just washed up at malware analysis now rip.

``` c
struct file_footer_struct
{
  byte footer_marker_head[16];
  WORD last_chunk_size;
  WORD total_chunk_count;
  WORD large_file_flag;
  WORD small_file_flag;
  DWORD default_chunk_size;
  DWORD footer_marker_tail;
  QWORD encrypted_chunk_count;
  byte encrypted_symmetric_key[1024];
};
```
| Field                   | Description                                                                   |
| ----------------------- | ----------------------------------------------------------------------------- |
| **footer_marker_head**        | First index in the **file_marker** of file struct                            |
| **last_chunk_size**            | Size of the last chunk at the end of the file                                          |
| **total_chunk_count**    | Total number of chunks to be encrypted               |
| **large_file_flag**           | Set to 1 if file is larger than 0x500000                                              |
| **small_file_flag**         | Set to 1 when file size high is less than 0 |
| **chunk_count**         | Number of chunks to encrypt in the file |
| **default_chunk_size**  | 0x100000 bytes |
| **footer_marker_tail**     | xxHash32 hash of footer_marker_head. Also the second index in the **file_marker** of file struct |
| **encrypted_chunk_count** | Total number of chunks successfully encrypted |
| **encrypted_symmetric_key** | encrypted AES key BLOB |


First, **PLAY** reads 0x428 bytes at the end of the file to check the file footer. If the file size is smaller than 0x428 bytes, the file is guaranteed to not be encrypted, so the malware moves to encrypt it immediately.

If the last 0x428 bytes is read successfully, the malware then checks if the **xxHash32** hash of the footer marker head is equal to the footer marker tail. If they are, then the file footer is confirmed to be valid, and the file is already encrypted.

If this is not the case, **PLAY** checks each DWORD in the footer marker head and compare it to the hard-coded values in the file structure. This is to check if the file footer is not encrypted, if the file footer is written but it has not been encrypted, or if the file is already encrypted.

![alt text](/uploads/PLAY33.PNG)

![alt text](/uploads/PLAY34.PNG)

*Figure 33, 34: Checking File Footer for Encryption State.*

### File Encryption

To encrypt a file from scratch, **PLAY** first generates an AES key to encrypt the file with.

It calls **BCryptGenRandom** to generate a random 0x20-byte buffer. Depending on the chaining mode specified in the file structure, the malware calls **BCryptSetProperty** to set the chaining properly for its AES provider handle.

Next, **BCryptGenerateSymmetricKey** is called on the randomly generated 0x20-byte buffer to generate the AES key handle.

![alt text](/uploads/PLAY35.PNG)

![alt text](/uploads/PLAY36.PNG)

![alt text](/uploads/PLAY37.PNG)

*Figure 35, 36, 37: Generating AES Key Handle.*

Next, to store the AES key in the file footer struct, **PLAY** calls **BCryptExportKey** to export the AES key into a 0x230-byte key blob. It also calls **BCryptGenRandom** to randomly generate a 0x10-byte IV and appends it after the key blob.

![alt text](/uploads/PLAY38.PNG)

![alt text](/uploads/PLAY39.PNG)

*Figure 38, 39: Exporting AES Key Blob & IV.*

Then, it calls **BCryptEncrypt** to encrypt the exported key blob and the IV using the RSA public key handle and writes the encrypted output to into a 0x400-byte buffer. This buffer is then copied to the **encrypted_symmetric_key** field of the file footer structure.

![alt text](/uploads/PLAY40.PNG)

*Figure 40: Encrypting AES Key Blob with RSA Public Key.*

**PLAY** then populates the file footer's other fields such as **footer_marker_head, footer_marker_tail, small_file_flag, and large_file_flag** with existing information from the file structure. The default chunk size is also set to 0x100000 bytes.

![alt text](/uploads/PLAY41.PNG)

*Figure 41: Populating File Footer Structure.*

Once the file footer is fully populated, the malware calls **SetFilePointerEx** to move the file pointer to the end of the file and calls **WriteFile** to write the structure there.

![alt text](/uploads/PLAY42.PNG)

*Figure 42: Writing File Footer Structure To End Of File.*

If the file size is greater than 0x500000 bytes, **PLAY** only encrypts the first and last chunk in the file.

![alt text](/uploads/PLAY43.PNG)

![alt text](/uploads/PLAY44.PNG)

*Figure 43, 44: Encrypting Large File's First & Last Chunk.*

The encrypting function consists of a **ReadFile** call to read the chunk data in the buffer in the file structure, a **BCryptEncrypt** call to encrypt the file using the AES key handle and the generated IV. After encryption is finished, the malware calls **WriteFile** to write the encrypted output to the file as well as the index of the chunk being encrypted in the file footer. This is potentially used to keep track of how many chunks have been encrypted in the case where corruption or interruption occurs.

![alt text](/uploads/PLAY45.PNG)

![alt text](/uploads/PLAY46.PNG)

![alt text](/uploads/PLAY46.PNG)

*Figure 45, 46, 47: Data Encrypting Function.*

If the file size is smaller than the default chunk size of 0x100000 bytes, the malware encrypts the entire file.

![alt text](/uploads/PLAY48.PNG)

*Figure 48: Encrypting Small File Whole.*

If the file size is somewhere in between 0x100000 and 0x500000, the malware encrypts it in 0x100000-byte chunks until it reaches the end of the file.

![alt text](/uploads/PLAY49.PNG)

*Figure 49: Encrypting Mid-Size File.*

Finally, after the file is encrypted, the malware changes its extension to **.PLAY** by calling **MoveFileW**. 

![alt text](/uploads/PLAY50.PNG)

*Figure 50: Appending Encrypted Extension.*


There is a small bug in the code that it always changes the extension of a file despite if encryption is successful or not due to the return value of the file encrypting function.

![alt text](/uploads/PLAY51.PNG)

*Figure 51: Encrypting Mid Size File.*

## References

https://www.bleepingcomputer.com/news/security/argentinas-judiciary-of-c-rdoba-hit-by-play-ransomware-attack/

https://helpdesk.privateinternetaccess.com/kb/articles/what-s-the-difference-between-aes-cbc-and-aes-gcm#:~:text=AES%2DGCM%20is%20a%20more,mathematics%20involved%20requiring%20serial%20encryption.