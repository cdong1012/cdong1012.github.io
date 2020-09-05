---
title: Reversing.kr - Easy Crack
categories:
  - Reverse Engineering
description: Writeup for Easy Crack challenge from Reversing.kr
---

# Reversing.kr - Easy Crack

## 1. Context

I've been working at Union Pacific for the network design team, so I have not had much practice with reverse engineering lately.

Since [FLARE-on 2020](http://flare-on.com/) from FireEye is coming next weekend, I figure that I should do some reversing this weekend to prepare for it.

I have picked [Reversing.kr](http://reversing.kr/index.php) to practice mainly because they have a lot of good Windows challenges for me to do. I have been trying to find them in normal CTFs, but most of them only makes reversing challenges for Linux machine.

It's not that I hate reversing in Linux, but reversing Windows application just feels nicer for some reason.

So here is my attempt at solving the first challenge called [Easy Crack](http://reversing.kr/challenge.php).

Note: I'll use mainly IDA Free and Binary Ninja during these reversing posts because I am too poor for IDA Pro and its decompiler. :disappointed:

## 2. Easy Crack

First, I run the executable to see its main functionality.

![alt text](/uploads/EC1.PNG)

It seems like the program creates a modal dialog box that takes in some input. Let's try typing in something and hit the submit button.

![alt text](/uploads/EC2.PNG)

So we know that we must enter a password. If the password is wrong, a popup will appear notifying us that it is wrong.

Let's open it in IDA. We know that the program must call [DialogBoxParam](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-dialogboxparama) to create the dialog box.

If we look for it, in function **sub_401000**(which is a typical starting point for Windows executable), we can see the call to _DialogBoxParam_ with the field _lpDialogFunc_ being the function **DialogFunc**!

![alt text](/uploads/EC3.PNG)

Therefore, we can assume that **DialogFunc** is the function that checks the validity of the password we type in. Let's analyze it!

![alt text](/uploads/EC4.PNG)

From here, we see that the branch **loc_40105E** will be the branch to end when the dialog box closes. We can assume that **loc_401049** is the main functionality because it is making a call to another function **sub_401080** passing in _hDlg_ from the closest _push_.

We know that _hDlg_ is the handle to the dialog box, so by passing this handle into the function, it's possible that the function will call functions such as [GetDlgItemTextA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdlgitemtexta) to get the password from the dialog box that we type in.

Let's see what's in **sub_401080**.

![alt text](/uploads/EC5.PNG)

We do see a call to **GetDlgItemTextA**! It seems like the call looks like this in C++.

```cpp
GetDlgItemTextA(hDlg, 0x3E8, String);
```

From this, we know that this call writes the item in the dialog text box into the variable _String_! If we look at the stack variables of this function, we has _String_, _var63_, _var62_, and _var60_.

These variables are suspiciously close to each other according to their offset. It seems like _String_ is the beginning of the password string that is retrieved from **GetDlgItemTextA**. _var63_ is 1 byte down from _String_, so _var63_ must be _String[1]_. Likewise, _var62_ is _String[2]_, and _var60_ is _String[4]_.

Let's just rename them and move on!

![alt text](/uploads/EC6.PNG)

Next, we see a comparison. The byte at index 1 of _String_ is being compared with 0x61(which is the character _a_ in ASCII). If this byte is 0x61, we move on. Else, we print out the **"Incorrect Password"** prompt at the **loc_401135** branch, so let's rename this branch to **incorrect_pass**. So we know the second character in our password is _a_.

![alt text](/uploads/EC7.PNG)

Here, we see our string being pushed as the parameter for the **sub_401150** function with the string **"5y"**. If this function returns 0, we move on, else we go to **incorrect_pass**. Note: the return value for x86 function calls is stored in **eax**.

Let's analyze **sub_401150** to see what it does.

![alt text](/uploads/EC8.PNG)

First, we move the _String[2]_ pointer to _edi_, then we move the string _"5y"_ to _esi_.

Then, we call **repe cmpsb**. **repe** means this call will happens while the bytes are still equal. **cmpsb** is a byte comparision of the current value pointed to by _esi_ and _edi_.

Here is the full definition of **cmpsb**.

    Compares byte at address DS:(E)SI with byte at address ES:(E)DI and sets the status flags accordingly

Basically, once this call finishes, _edi_ points to the first character in _String[2]_ that differs from the string _"5y"_, and the same is with _esi_.

Next, we check if the bytes before the current _edi_ and _esi_ are equal to each other. If they are equals, _ecx_ remains 0, else _ecx_ is changed.

Then, _ecx_ is written into _eax_ as the return value for the function.

To wrap it up, this function just checks if the 2 bytes _String[2]_ and _String[3]_ are equal to _"5y"_. If they are, return 0, else return some other non-zero value!.

Since we want this to return 0, we must have these two characters from our password to be _5y_.

Here is what our password looks like so far (\* means wildcard).

    *a5y

Let's move on!

![alt text](/uploads/EC9.PNG)

First, we see that the string _"R3versing"_ is passed into _esi_, and the pointer _String[4]_ is passed into _eax_. My assumption is that this is just a string comparison loop, but let's walk through the assembly code to see what it is!

At the beginning of the loop, the bytes at both the pointers are passed into _edx_ and _ebx_ and compared. If they are not equal, we branch to **loc_401102**. This branch basically just loads 0xFFFFFFFF into _eax_.

Notice that this branch and **loc_4010FE** both branches into **loc_401107**, and **loc_401107** checks if _eax_ is 0. If _eax_ is 0, we move on, else we branch to **incorrect_pass**.

So, let's rename **loc_401102** into **str_cmp_fail** and **loc_4010FE** into **str_cmp_succeed**.

![alt text](/uploads/EC10.PNG)

So here, we compare each character from the two string one by one. If we reach the end of _String[4]_ and we still haven't branch into **str_cmp_fail**, we know that we have succeed and the strings are the same!

After every loop, the pointers are increment every time and the process occurs until we branch into either **str_cmp_fail** or **str_cmp_succeed**. So basically, like we assumed, this is just a string comparison loop!

Now, our current password should look like this.

    *a5yR3versing

Let's move forward.

![alt text](/uploads/EC11.PNG)

Finally, we are comparing the first character of _String_ with 0x45(which is the character _E_ in ASCII). If they equal, we print _"Incorrect Password"_, else we print the congratulations message!!

So our final password is **Ea5yR3versing**!! Let's run the program and type it in!

![alt text](/uploads/EC12.PNG)

## 3. Recap

This reversing challenge is pretty simple, but it's a pretty good practice for me to start reading x86 Assembly and reversing again!
