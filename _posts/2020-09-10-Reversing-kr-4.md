---
title: Reversing.kr - Ransomware
categories:
  - Reverse Engineering
description: Write-up for Ransomware challenge from Reversing.kr
---

# Reversing.kr - Ransomware

## 1. Context

This is the fourth post of my reversing series following the previous posts about [Reversing.kr](http://reversing.kr/index.php).

This time, the challenge is **Ransomware**. From this name, I guess we will be dealing with encrypted files!

## 2. Ransomware

First, when we unzip the zip file, we get 2 files, _file_ and _ransomware.exe_.

Since there is no file extension on _file_, I suspect it being in binary form and encrypted. Let's open it in [HxD](https://mh-nexus.de/en/hxd/) to check it.

![alt text](/uploads/Ransom1.PNG)

This file just contains random-looking bytes. I don't recognize any of the normal file type here, so we must try to unencrypt it.

Let's run the executable to see what its functionality is.

![alt text](/uploads/Ransom2.PNG)

The executable just prompt us for a key, and then it writes stuff into _file_ accordingly. If we view _file_ content again, this will look oddly similar to an encrypted Windows PE file.

![alt text](/uploads/Ransom3.PNG)

Let's compare that with a valid Windows PE file.

![alt text](/uploads/Ransom4.PNG)

It seems like they are using a XOR encryption to encrypt every byte except byte **\x00**. Interesting! Let's throw it into IDA!

![alt text](/uploads/Ransom5.PNG)

So this executable is encrypted with UPX. Let's just quickly unpack it using UPX.

![alt text](/uploads/Ransom6.PNG)

Now that we have unpacked it, let's view it in IDA and see what we get.

![alt text](/uploads/Ransom7.PNG)

Yikes, I have never seen this from IDA. This function is too large that IDA graph view can't even display it. Also, since it is too big, IDA becomes really laggy and I can not get anything done with it.

Let's try using **x64dbg** to debug it and see why it's so long.

![alt text](/uploads/Ransom8.PNG)

At _0x44A775_, we can see the normal executing code containing **printf** and **scanf** and all that, but what is all that crap above it? It seems like just a bunch of useless instruction that cancels each other out(push, pop, pushad, popad, and nop).

No wonder why our code is so long. The author of this challenge just pad the executable code with this so we can't view it in IDA. It doesn't matter tho because we can just patch and skip out on all of it. If we scroll up a bit, we'll see some valid code again at _0x43819F_.

![alt text](/uploads/Ransom9.PNG)

This is super far away from _0x44A775_ with a bunch of useless instruction between. Let's just try and have a **jmp** instruction at the end to jump directly to _0x44A775_. We can patch it using **OllyDbg** cause it's easier compared to **x64dbg**!

![alt text](/uploads/Ransom10.PNG)

After doing this a few time, we can eliminate all the useless code, dump it out through **OllyDbg**, and start disassemble it in IDA!

![alt text](/uploads/Ransom11.PNG)

Here, we can see the two **printf** call, following by a **scanf** call just like when we observe the executable's functionality. Notice how **offset byte_44D370** was pushed on the stack as the parameter for scanf, we know the pointer to our key will be there after the call. Then, the pointer is written into **var_18**, so let's rename **var_18** to **input_key_pointer** and move on.

![alt text](/uploads/Ransom12.PNG)

Here, we see **input_key_pointer + 1** is stored into **var_1C**, so **var_1C** is a pointer pointing to the character at index 1 of the key.

Then, we loop through every byte, increment **input_key_pointer** until we find the null terminator. At this point, the **input_key_pointer** contains the pointer pointing to the byte after the null terminator.

After that, we subtract the difference between the current **input_key_pointer** with **var_1C** to get the length of the input key! This length is stored in **var_24**, so let's rename it and move on.

![alt text](/uploads/Ransom13.PNG)

Next, we see a call to **fopen**, and the file stream returned is stored in the variable **File**. Then, this variable is check to be null or not. If it is, we exit promptly. If it is not, it means we can open the file _file_ and we will branch to the right!

![alt text](/uploads/Ransom14.PNG)

Basically, it looks something like this in C

```c
fseek(File, 0, SEEK_END);
var_10 = ftell(File);
rewind(File);
```

In the first instruction, we change the stream pointer to the end of the file. In the second instruction, the pointer to the end of the file is stored in **var_10**(let's change that into **end_pointer**). After that, a **rewind** call is used to set the stream pointer back to the beginning. Basically, this block of code just gets the pointer to the end of the file!

![alt text](/uploads/Ransom15.PNG)

Now, we have a loop! This is just a while loop that goes until **feof** returns a non-zero value (the end of the file is reach). In the body of this loop, **var_8** is basically a pointer to a counter variable that counts up from 0. We just read a byte from the file using **fgetc** each time, write it into **byte_5415B8**, and increment the pointer. Let's change **byte_5415B8** into **file_buffer** because at the end of the loop, this memory buffer will contain the entire file, and the **var_8** counter is reset to 0!

![alt text](/uploads/Ransom16.PNG)

Here, we have reach the final loop of this function. This loop executes until the **var_8** counter equals to the **end_pointer** variable. In this code block, there are two XOR calls.

The first one is xoring the current file byte with the current character in the key, and the next one is xoring the result of the previous with 0x99.

After the loop exits, we will write the entire **file_buffer** back into _file_.

So there we go, we have had the algorithm to unencrypt the executable. Let's write a python script for that. Since at position 0x4E to 0x73 in any executable file, there is the DOS stub with the string _"This program cannot be run in DOS mode"_ there. We can reverse engineer our way back to find the correct key by XOR-ing that string with 0x99 and whatever bytes in that range in the _file_ file.

```python
file = open('file', 'rb')
byte_array = bytearray(file.read(0x74)) # byte_array contains the first 0x73 bytes of file
byte_array_ori = b'This program cannot be run in DOS mode'
file.close()
key = ''
for i in range(0x4E, 0x74):
    key += chr((byte_array[i] ^ byte_array_ori[i - 0x4E]) ^ 0xFF)

print(key)
```

After this, we will see a string like this `letsplaychessletsplaychessletsplayches`. Since the key is repeated to encrypt the entire file, we can extract the key from this cluster. The real key is **letsplaychess**!

If we run the original executable and give this key as the input, we will see _file_ changed into an executable file!

![alt text](/uploads/Ransom17.PNG)

When we execute this file, we will see the flag being printed out!

![alt text](/uploads/Ransom18.PNG)

## 3. Recap

Overall, this challenge took me a while to do. The useless bytes patching took most of my effort because I'm not too experienced with file patching. The rest is pretty simple with just a XOR-encryption algorithm using the input key!

Also, a huge hint to help me figure out that the final form of file is an executable was how the encrypted file looks like after my first run. It would have been much much harder if the author hides that, but oh well! It was a fun challenge overall.
