# ToC
- [Code Injection Techniques](#code-injection-techniques)
  * [DLL Injection *(Dynamic Library Injection)*](#dll-injection---dynamic-library-injection--)
  * [Process Hollowing *(Replacement of the image in memory of a process)*](#process-hollowing---replacement-of-the-image-in-memory-of-a-process--)
  * [Process Doppelgänging *(Running a binary in a "transactional" state invisible to VA)*](#process-doppelg-nging---running-a-binary-in-a--transactional--state-invisible-to-va--)
  * [Process Ghosting *(miscling of a legitimate executable before loading)*](#process-ghosting---miscling-of-a-legitimate-executable-before-loading--)
  * [Thread Execution Hijacking *(Injection into an existing thread of a legitimate process)*](#thread-execution-hijacking---injection-into-an-existing-thread-of-a-legitimate-process--)
  * [Early Bird Injection *(Code injection before full creation of the target process)*](#early-bird-injection---code-injection-before-full-creation-of-the-target-process--)
- [Advanced Injection Techniques](#advanced-injection-techniques)
  * [EtwpCreateEtwThread Abuse *(Chip of an ETW thread for executing code)*](#etwpcreateetwthread-abuse---chip-of-an-etw-thread-for-executing-code--)
  * [Atom Bombing *(Use of "atom tables" to inject code without a suspicious API)*](#atom-bombing---use-of--atom-tables--to-inject-code-without-a-suspicious-api--)
  * [Heaven’s Gate *(x86 x 64 Injection)*](#heaven-s-gate---x86-x-64-injection--)
- [EDR/AV bypass techniques](#edr-av-bypass-techniques)
  * [Syscall Direct *(Syscall Spoofing)*](#syscall-direct---syscall-spoofing--)
  * [PID Spoofing Parent *(PPID Spoofing)*](#pid-spoofing-parent---ppid-spoofing--)
  * [Indirect Syscalls - API Hook Evasion](#indirect-syscalls---api-hook-evasion)
- [Examples of Malware Using These Techniques](#examples-of-malware-using-these-techniques)
  * [Cobalt Strike *(**Process Injection**, **Syscall Direct**)*](#cobalt-strike-----process-injection------syscall-direct----)
  * [TrickBot *(**Process Hollowing**, **APC Injection**)*](#trickbot-----process-hollowing------apc-injection----)
  * [QakBot *(**Process Ghosting**, **Parent PID Spoofing**)*](#qakbot-----process-ghosting------parent-pid-spoofing----)
  * [Metasploit *(**DLL Injection**, **Early Bird Injection**)*](#metasploit-----dll-injection------early-bird-injection----)
 


# Introduction
### Hijacking and Code Injection (Code Injection)
*(Techniques to execute malicious code in legitimate processes by manipulating the memory or execution mechanisms of Windows.)*

*The purpose of code injection is to run malware through a legitimate process to circumvent protections such as antivirus (AV) and behavioural detection solutions (BDUs). These methods also make it possible to escape forensic analysis and to maintain persistence in the system.*

# Code Injection Techniques
*Conventional injection methods use Windows APIs to write and execute code in a remote process.*
## DLL Injection *(Dynamic Library Injection)*
- Charges a malicious DLL into a legitimate process.
- Use of ```LoadLibrary```, ```CreateRemoteThread```, ```SetWindowsHookEx```.
- Example:
```
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
LPVOID pAddr = VirtualAllocEx(hProcess, NULL, dllSize, MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(hProcess, pAddr, dllPath, dllSize, NULL);
HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pAddr, 0, NULL);
```
## Process Hollowing *(Replacement of the image in memory of a process)*
- Creation of a suspended process (```CreateProcess```).
- Replacement of the binary image by malicious code via ```NtUnmapViewOfSection```.
- Restarting the process via ```ResumeThread```.

## Process Doppelgänging *(Running a binary in a "transactional" state invisible to VA)*
- Exploit ```NTFS Transaction API```(```TxF```).
- Allows the malicious process to be obscured by passing it off as a legitimate executable.
- Does not create artifacts on the disk.

## Process Ghosting *(miscling of a legitimate executable before loading)*
- Creation of a malicious binary file but never actually written on the disk.
- Windows loads the executable without the AV being able to analyse it.

## Thread Execution Hijacking *(Injection into an existing thread of a legitimate process)*
- Injection via ```SuspendThread```, ```VirtualAllocEx```, ```SetThreadContext```, ```ResumeThread```.
- Allows you to hijack an existing thread to execute malicious code.

## Early Bird Injection *(Code injection before full creation of the target process)*
- The process is suspended at start-up (```CreateProcess```).
- Injection before the BDU can analyse the executable.
- Rapid and stealthy execution of the injected shellcode.

# Advanced Injection Techniques
*More sophisticated methods used to circumvent modern detection solutions.*
## APC Injection *(Asynchronous Procedure Call)*
- Execution of a shellcode via a ```APC Queue``` on a pending thread.
- Use of ```QueueUserAPC```.
- Execution in ```explorer.exe``` to mask activity.

## EtwpCreateEtwThread Abuse *(Chip of an ETW thread for executing code)*
- Exploit EtwpCreateEtwThreadto execute a shellcode in a hidden thread.

## Atom Bombing *(Use of "atom tables" to inject code without a suspicious API)*
- Store the shellcode in a ```Global Atom Table```.
- A legitimate process reads this table and executes the malicious code.

## Heaven’s Gate *(x86 x 64 Injection)*
- Allows a 32-bit process to run 64-bit code bypassing conventional Windows APIs.
- Uses ```segment selectors```(```FS``` and ```GS```) to switch between x86 and x64.

# EDR/AV bypass techniques
## Syscall Direct *(Syscall Spoofing)*
- Instead of calling Windows APIs (```NtAllocateVirtualMemory```), malware directly calls system syscalls by avoiding ```ntdll.dll```.
-

## PID Spoofing Parent *(PPID Spoofing)*
- Amendment of ```Parent Process ID``` to make it appear that the malicious process has been initiated by a legitimate process (```explorer.exe```).
- Example viaCreateProcessin PowerShell:
```
$si = New-Object Startupinfo
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
$si.dwFlags = 0x1
$si.wShowWindow = 0
Start-Process -FilePath "cmd.exe" -NoNewWindow -PassThru
```

## Indirect Syscalls - API Hook Evasion
- Bypasses hooks placed by EDRs by calling syscalls indirectly.
- Use of ```NtMapViewOfSection```, ```NtTestAlert``` to escape detection.

# Examples of Malware Using These Techniques
## Cobalt Strike *(**Process Injection**, **Syscall Direct**)*
- Injecting payloads into legitimate processes (```explorer.exe```).
- Uses ```Syscall Spoofing``` to bypass EDRs.

## TrickBot *(**Process Hollowing**, **APC Injection**)*
- Turned ```svchost.exe``` to execute its malicious modules.

## QakBot *(**Process Ghosting**, **Parent PID Spoofing**)*
- Performs the code in ```explorer.exe``` to escape the AVs.

## Metasploit *(**DLL Injection**, **Early Bird Injection**)*
- Payloads generated with ```msfvenom``` use various methods of injection.
















