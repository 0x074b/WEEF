# Introduction
### Hijacking and Code Injection (Code Injection)
*(Techniques to execute malicious code in legitimate processes by manipulating the memory or execution mechanisms of Windows.)*

*The purpose of code injection is to run malware through a legitimate process to circumvent protections such as antivirus (AV) and behavioural detection solutions (BDUs). These methods also make it possible to escape forensic analysis and to maintain persistence in the system.*

# Code Injection Techniques
*Conventional injection methods use Windows APIs to write and execute code in a remote process.*
#### DLL Injection (Dynamic Library Injection)*
- Charges a malicious DLL into a legitimate process.
- Use of ```LoadLibrary```, ```CreateRemoteThread```, ```SetWindowsHookEx```.
- Example:
```
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
LPVOID pAddr = VirtualAllocEx(hProcess, NULL, dllSize, MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(hProcess, pAddr, dllPath, dllSize, NULL);
HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pAddr, 0, NULL);
```
#### Process Hollowing *(Replacement of the image in memory of a process)*
- Creation of a suspended process (```CreateProcess```).
- Replacement of the binary image by malicious code via ```NtUnmapViewOfSection```.
- Restarting the process via ```ResumeThread```.

#### Process Doppelgänging *(Running a binary in a "transactional" state invisible to VA)*
- Exploit ```NTFS Transaction API```(```TxF```).
- Allows the malicious process to be obscured by passing it off as a legitimate executable.
- Does not create artifacts on the disk.

#### Process Ghosting *(miscling of a legitimate executable before loading)*
- Creation of a malicious binary file but never actually written on the disk.
- Windows loads the executable without the AV being able to analyse it.

#### Thread Execution Hijacking *(Injection into an existing thread of a legitimate process)*
- Injection via ```SuspendThread```, ```VirtualAllocEx```, ```SetThreadContext```, ```ResumeThread```.
- Allows you to hijack an existing thread to execute malicious code.

#### Early Bird Injection *(Code injection before full creation of the target process)*
- The process is suspended at start-up (```CreateProcess```).
- Injection before the BDU can analyse the executable.
- Rapid and stealthy execution of the injected shellcode.

# Advanced Injection Techniques













