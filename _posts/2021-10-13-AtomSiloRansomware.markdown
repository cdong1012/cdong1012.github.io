---
title: AtomSilo Ransomware
categories:
  - Reverse Engineering
description: Malware Analysis Report - AtomSilo Ransomware
---

# AtomSilo Ransomware

## Contents

- [AtomSilo Ransomware](#atomsilo-ransomware)
  - [Contents](#contents)
  - [Overview](#overview)
  - [IOCS](#iocs)
  - [Ransom Note](#ransom-note)
- [Static Code Analysis](#static-code-analysis)
  - [Cryptographic Keys Setup](#cryptographic-keys-setup)
  - [Run-Once Mutex](#run-once-mutex)
  - [Launching Encryption Threads](#launching-encryption-threads)
  - [Encryption Threads](#encryption-threads)
    - [Dropping Ransom Note](#dropping-ransom-note)
    - [DFS Traversal](#dfs-traversal)
    - [File Encryption](#file-encryption)
  - [How To Decrypt](#how-to-decrypt)
  - [References](#references)

## Overview

This is my analysis for **AtomSilo Ransomware**.

**AtomSilo** uses the standard hybrid-cryptography scheme of **RSA-512** and **AES** to encrypt files and protect its keys.

Since it fails to utilize multithreading and uses a DFS algorithm to traverse through directories, **AtomSilo's** encryption is quite slow.

The malware is relatively short and simple to analyze, so it's definitely a beginner-friendly choice for those who want to get into ransomware analysis!

![alt text](/uploads/AtomSilo1.PNG)

*Figure 1: AtomSilo leak site.*

## IOCS

This sample is a 64-bit Windows executable.

**MD5**: 81f01a9c29bae0cfa1ab015738adc5cc

**SHA256**: 7a5999c54f4588ff1581d03938b7dcbd874ee871254e2018b98ef911ae6c8dee

**Sample**: [https://bazaar.abuse.ch/sample/7a5999c54f4588ff1581d03938b7dcbd874ee871254e2018b98ef911ae6c8dee/](https://bazaar.abuse.ch/sample/7a5999c54f4588ff1581d03938b7dcbd874ee871254e2018b98ef911ae6c8dee/)

## Ransom Note

The content of the ransom note is stored in plaintext in **AtomSilo's** executable. The encrypted victim's **RSA** public key is appended to the end of the note before the files are dropped on the system.

The ransom note filename is in the form of **README-FILE-[Computer Name]-[Starting Timestamp].hta** or **index.html**.

![alt text](/uploads/AtomSilo2.PNG)

*Figure 2: AtomSilo ransom note.*

Below is the full content of the ransom note file dropped on my machine.

``` html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Atom Slio: Instructions</title>
    <HTA:APPLICATION APPLICATIONNAME="Atom Slio" SCROLL="yes" SINGLEINSTANCE="yes" WINDOWSTATE="maximize">
        
    <style type="text/css">
    .text{
        text-align:center;
    }
    a {
        color: #04a;
        text-decoration: none;
    }
    a:hover {
        text-decoration: underline;
    }
    body {
        background-color: #e7e7e7;
        color: #222;
        font-family: "Lucida Sans Unicode", "Lucida Grande", sans-serif;
        font-size: 13pt;
        line-height: 19pt;
    }
    body, h1 {
        margin: 0;
        padding: 0;
    }
    hr {
        color: #bda;
        height: 2pt;
        margin: 1.5%;
    }
    h1 {
        color: #555;
        font-size: 14pt;
    }
    ol {
        padding-left: 2.5%;
    }
    ol li {
        padding-bottom: 13pt;
    }
    small {
        color: #555;
        font-size: 11pt;
    }
    .button:hover {
        text-decoration: underline;
    }
    .container {
        background-color: #fff;
        border: 2pt solid #c7c7c7;
        margin: 5%;
        min-width: 850px;
        padding: 2.5%;
    }
    .header {
        border-bottom: 2pt solid #c7c7c7;
        margin-bottom: 2.5%;
        padding-bottom: 2.5%;
    }
    .hr {
        background: #bda;
        display: block;
        height: 2pt;
        margin-top: 1.5%;
        margin-bottom: 1.5%;
        overflow: hidden;
        width: 100%;
    }
    .info {
        background-color: #f3f3fc;
        border: 2pt solid #bda;
        display: inline-block;
        padding: 1%;
        text-align: center;
        box-sizing:border-box;
        border-radius:20px;
    }
    .info1 {
        background-color: #f3f3fc;
        border: 2pt solid #bda;
        display: inline-block;
        padding: 1%;
        text-align: center;
        box-sizing:border-box;
        border-radius:20px;
    }
    .h {
        display: none;
    }
    .ml1{
    position:absolute;width:50%;height:10rem;left:-211px;top:0;background:#f3f3fc;border:1px solid #cfd3da;box-sizing:border-box;padding:2% 2%
    }
    </style>
</head>
<body>

    <div class="container">
        <div class="header">
            <h1>Atom Slio</h1>
            <small id="title">Instructions</small>
        </div>

                <div class="text">
                <span style="color:#f71b3a;font-size:40px">WARNING! YOUR FILES ARE ENCRYPTED AND LEAKED!</span>
                </div>
                <hr></hr>
                <div class="info1">
                <p>We are AtomSilo.Sorry to inform you that your files has been obtained and encrypted by us.</p>
                <p>But don’t worry, your files are safe, provided that you are willing to pay the ransom.</p>
                <p>Any forced shutdown or attempts to restore your files with the thrid-party software will be <span style="color:#f71b3a">damage your files permanently!</span></p> 
                <p>The only way to decrypt your files safely is to buy the special decryption software from us. </p>
                <p>The price of decryption software is <span style="color:#f71b3a">1000000 dollars</span>. <br>If you pay within 48 hours, you only need to pay <span style="color:#f71b3a">500000 dollars</span>. No price reduction is accepted.</p>
                <p>We only accept Bitcoin payment,you can buy it from bitpay,coinbase,binance or others. </p>
                <p>You have five days to decide whether to pay or not. After a week, we will no longer provide decryption tools and publish your files</p>
                 
                </div>
                <hr></hr>
                    <div align="center">
                    <span style="color:#f71b3a;font-size:200%">Time starts at 0:00 on September 11</span>
                    <hr></hr>
                    <span style="color:#f71b3a;font-size:300%">
                    <a>Survival time：</a>
                    <span id="td"></span>
                    <span id="th"></span>
                    <span id="tm"></span>
                    <span id="ts"></span>
                    </span>
                    </div>
                    <script type="text/javascript">
                    function getRTime(){
                    var EndTime= new Date('2021/09/16 00:00:00');
                    var NowTime = new Date();
                    var t =EndTime.getTime() - NowTime.getTime();
                     
                    var d=Math.floor(t/1000/60/60/24);
                    var h=Math.floor(t/1000/60/60%24);
                    var m=Math.floor(t/1000/60%60);
                    var s=Math.floor(t/1000%60);

                    document.getElementById("td").innerHTML = d + " Day ";
                    document.getElementById("th").innerHTML = h + " Hour ";
                    document.getElementById("tm").innerHTML = m + " Min ";
                    document.getElementById("ts").innerHTML = s + " Sec ";
                    }
                    setInterval(getRTime,1000);
                    </script>
                    
                <hr></hr>
                <p>You can contact us with the following email:
                <p><a href="mailto:arvato@atomsilo.com"><span class="info">Email:arvato@atomsilo.com</span></a></p>
                <p>If this email can't be contacted, you can find the latest email address on the following website:</p>
                <p><span class="info"><a href="hxxp://<redacted>[.]onion" target="_blank">hxxp://<redacted>[.]onion</a></span></p>
                <hr>
                <p>If you don’t know how to open this dark web site, please follow the steps below to installation and use TorBrowser:</p>
                <ol>
                    <li>run your Internet browser</li>
                    <li>enter or copy the address <a href="hxxps://www[.]torproject[.]org/download/download-easy[.]html[.]en" target="_blank">hxxps://www[.]torproject[.]org/download/download-easy[.]html[.]en</a> into the address bar of your browser and press ENTER</li>
                    <li>wait for the site loading</li>
                    <li>on the site you will be offered to download TorBrowser; download and run it, follow the installation instructions, wait until the installation is completed</li>
                    <li>run TorBrowser</li>
                    <li>connect with the button "Connect" (if you use the English version)</li>
                    <li>a normal Internet browser window will be opened after the initialization</li>
                    <li>type or copy the address in this browser address bar and press ENTER</li>
                    <li>the site should be loaded; if for some reason the site is not loading wait for a moment and try again.</li>
                </ol>
                <p>If you have any problems during installation or use of TorBrowser, please, visit <a href="hxxps://www[.]youtube[.]com/results?search_query=Install+Tor+Browser+Windows" target="_blank">hxxps://www[.]youtube[.]com</a> and type request in the search bar "Install TorBrowser Windows" and you will find a lot of training videos about TorBrowser installation and use.</p>
                <hr>
                <p><strong>Additional information:</strong></p>
                <p>You will find the instructions ("README-FILE-#COMPUTER#-#TIME#.hta") for restoring your files in any folder with your encrypted files.</p>
                <p>The instructions "README-FILE-#COMPUTER#-#TIME#.hta" in the folders with your encrypted files are not viruses! The instructions "README-FILE-#COMPUTER#-#TIME#.hta" will help you to decrypt your files.</p>
                <p>Remember! The worst situation already happened and now the future of your files depends on your determination and speed of your actions.</p>
            </div>

    <span class="h"><asf>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</asf><csf>3</csf><bsf>MSEDGEWIN10</bsf></span></body></html>
```

# Static Code Analysis

## Cryptographic Keys Setup

**AtomSilo** uses a simple hybrid cryptographic approach using **RSA** and **AES** from [the CryptoPP library](https://github.com/weidai11/cryptopp) to encrypt files. The malware first randomly generates a public-private key pair for the victim and stores them in global variables.

Then it encrypts the victim's public key using its own hard-coded RSA public key and wipes the generated victim public key from memory. Since the **CryptoPP** code for this is nasty, the best way to analyze these functions is probably pulling function signatures down from **Lumina** and making assumptions based on the functions getting called.

![alt text](/uploads/AtomSilo3.PNG)

*Figure 3: Cryptographic Keys Setup.*

Since the victim's public key is required to decrypt files later, **AtomSilo** clears it out in memory after encrypting and storing the result to avoid the key being recovered from memory.

Below is the hard-coded **AtomSilo** public RSA key.

![alt text](/uploads/AtomSilo4.PNG)

*Figure 4: AtomSilo Public RSA Key.*

## Run-Once Mutex

**AtomSilo** calls **CreateMutexA** to check if the mutex with name **"8d5e957f297893487bd98fa830fa6413"** already exists, and if it does, the malware exits immediately. This is to avoid having multiple instances of the malware running at the same time.

![alt text](/uploads/AtomSilo5.PNG)

*Figure 5: Run-Once Mutex Check.*

## Launching Encryption Threads

**AtomSilo** attempts to use multithreading to speed up traversing and encrypting files on the system. It iterates through a list of drive names from "a:" to "z:" and spawns a new thread to encrypt each.

![alt text](/uploads/AtomSilo6.PNG)

*Figure 6: Spawning Encryption Threads.*

![alt text](/uploads/AtomSilo7.PNG)

*Figure 7: List Of Drive Names.*

The idea for multithreading is definitely there, but spawning threads this way is inefficient since the total throughputs and speed will be skewed toward the drive that has the most files inside.

## Encryption Threads

### Dropping Ransom Note

For each encountered directory, **AtomSilo** drops a ransom note in it.

First, the malware decrypts the following stack string and formats it as below.

``` HTML
<asf>
</asf>
<csf>3</csf>
<bsf>[Computer Name]</bsf></span></body></html>
[Directory Name]\index.html
[Directory Name]\README-FILE-[Computer Name]-[Starting Timestamp].hta
```

![alt text](/uploads/AtomSilo8.PNG)

*Figure 8: Resolving HTML Tags & Filename.*

The ransom note's filenames are used depending on its dropped location. When **AtomSilo** encounters any file with the extensions **.php**, **.asp**, **.jsp**, or **.html**, it uses **[Directory Name]\index.html** as the ransom note filename. For any other directory, it uses **[Directory Name]\README-FILE-[Computer Name]-[Starting Timestamp].hta**.

Finally, **AtomSilo** writes the content of the ransom note in in the following format.

``` HTML
[Ransom Note Content]<asf>[Victim Encrypted RSA Public Key]</asf><csf>3</csf><bsf>[Computer Name]</bsf></span></body></html>
```

![alt text](/uploads/AtomSilo9.PNG)

*Figure 9: Writing Ransom Note Content.*

### DFS Traversal

Each thread uses DFS to traverse a directory being passed into it. First, to look for all files and subdirectories, it uses the standard API calls **FindFirstFileA** and **FindNextFileA**.

**AtomSilo** stores a list of names to avoid encrypting in memory to iterate and check for each file/directory encountered. If the name of the file/directory is in the list, it is skipped and not encrypted.

![alt text](/uploads/AtomSilo10.PNG)

*Figure 10: Traversing & Skipping Files.*

The list of file/directory names to avoid is shown below.

``` rust
Boot, Windows, Windows.old, Tor Browser, Internet Explorer, Google,
Opera, Opera Software,  Mozilla, Mozilla Firefox, $Recycle.Bin, ProgramData,
All Users, autorun.inf, index.html, boot.ini, bootfont.bin, bootsect.bak,
bootmgr, bootmgr.efi, bootmgfw.efi, desktop.ini, iconcache.db, ntldr,
ntuser.dat, ntuser.dat.log, ntuser.ini, thumbs.db, #recycle, ..
```

If **AtomSilo** encounters a subdirectory, the malware appends its name to the current directory path, drops a ransom note inside, and passes the path to its traversal function to recursively go through it. No need for me to discuss how much of a speed boost the ransomware gets out of this.

![alt text](/uploads/AtomSilo11.PNG)

*Figure 11: Traversing Subdirectories With DFS.*

If **AtomSilo** encounters a file, the malware checks if the filename contains the following extensions.

``` ext
.atomsilo, .hta, .html, .exe, .dll, .cpl, .ini, .cab, .cur, .cpl,
.cur, .drv, .hlp, .icl, .icns, .ico, .idx, .sys, .spl, .ocx
```

If it does, the file is skipped and not encrypted.

![alt text](/uploads/AtomSilo12.PNG)

*Figure 12: Skipping Files Based On Extension.*

As discussed above, when **AtomSilo** encounters any file with the extensions **.php**, **.asp**, **.jsp**, or **.html**, it drops the ransom note in the path **[Directory Name]\index.html**. Finally, it passes the file path to a function to encrypt it.

![alt text](/uploads/AtomSilo13.PNG)

*Figure 13: Dropping Ransom Note & Encrypting File.*

### File Encryption

For each file to be encrypted, **AtomSilo** randomly generates a 32-byte **AES** key. First, it gets the current system time and uses that as the seed for the C++ pseudo-random number generator through **srand**. Using this, the malware generates a random string of 32 characters, and each character is randomly chosen to be a lower-case letter, upper-case letter, or a number between 0-9.

![alt text](/uploads/AtomSilo14.PNG)

*Figure 14: Randomly Generating AES Key.*

Next, the **AES** key is encrypted using the victim's RSA private key.

![alt text](/uploads/AtomSilo15.PNG)

*Figure 15: Encrypting AES Key With Victim Private Key.*

**AtomSilo** then opens the file using **CreateFileA** and maps it to the address space of the current process to read and write directly using **CreateFileMappingA** and **MapViewOfFile**.

![alt text](/uploads/AtomSilo16.PNG)

*Figure 16: Retrieving File Handle & Mapping To Memory.*

Prior to encrypting the file, the malware writes the encrypted AES key to the last 0x210 bytes at the end of the file.

![alt text](/uploads/AtomSilo17.PNG)

*Figure 17: Writing Encrypted AES Key To File.*

Finally, **AtomSilo** encrypts the file using the AES key with the AES implementation from **CryptoPP**, closes the file mapping handle, and appends **".ATOMSILO"** to the end of the filename.

![alt text](/uploads/AtomSilo18.PNG)

*Figure 18: Encrypting & Changing File Extension.*

## How To Decrypt

The victim's encrypted public RSA key is appended near the end of the ransom note, which is encrypted using **AtomSilo's** public RSA key. Therefore, to decrypt the victim's public RSA key, **AtomSilo's** private RSA key is required.

To decrypt a file encrypted by **AtomSilo**, the encrypted AES key can be extracted from the end of the file. Since the AES key is encrypted using the victim's private RSA key, it can be decrypted using the victim's public RSA key.

## References

https://github.com/weidai11/cryptopp