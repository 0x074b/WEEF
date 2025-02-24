# Introduction
### User Mode Subversion (Userland Mode Escape)
*(Techniques to avoid antivirus (AV) detection and Endpoint Detection and Response (EDR) by manipulating Windows APIs and the user environment.)*

*These methods exploit Windows mechanisms in user mode to avoid security solutions that monitor system calls, processes, and abnormal behaviors.*

# API masking and handling techniques
#### Hooking API Evasion *(Off-Disablement or Bypassing Hooks Placed by EDRs)*
- EDRs place hooks on APIs like ```NtOpenProcess```, ```NtReadVirtualMemory```, ```NtWriteVirtualMemory``` to monitor suspicious behaviour.
- A malware can bypass these hooks by:
  - Restoration of the original functions (```unhooking```).
  - Use of ```syscall direct``` to avoid instrumented APIs.
  - Injecting a clean copy of ```ntdll.dll``` to avoid hooks placed in memory.

#### Direct Syscalls - Syscall Spoofing
- Avoid Windows APIs and call them directly ```syscalls``` via instruction ```syscall``` as an assembler.
- Example of an assembly code (Windows x64):
```
mov r10, rcx
mov eax, <Syscall Number>
syscall
ret
```
- Inverts EDRs that place hooks at the userland level.
#### Unhooking of Windows APIs
- Restoration of original refilling APIs ```ntdll.dll``` clean from the disk.
- Bypassing hooks with ```memcpy``` to crush the EDR trampolines.

#### PID Spoofing Parent *(PPID Spoofing)*
- Modification of the Parent Process ID to suggest that a malicious process has been initiated by a legitimate process (```explorer.exe```, ```winlogon.exe```).
- Circumses detection based on process tree analysis.
- Example in cpp using ```NtQueryInformationProcess```:
```
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLength);
```
#### Process Ghosting *(running an executable without leaving a trace on the disk)*
- Creation of a binary file, but never actually written on the disk before its execution.
- Windows loads the executable before the AV can analyze it.
- Alternative to ```Process Doppelgänging```.

#### Process Hollowing *(Injecting and Executing a Legitiless Process)*
- Creation of a suspended process (```CreateProcess```)
- Visoring of the legitimate code (```NtUnmapViewOfSection```)
- Injection of the malicious code (```WriteProcessMemory```)
- Resumption of execution (```ResumeThread```)
- Example in PowerShell:
```
Start-Process -FilePath "notepad.exe" -WindowStyle Hidden
```

#### Early Bird Injection *(Code injection before the EDR can analyse the process)*
- Injecting shellcode before the end of process initialisation (```CreateProcess Suspended```).
- Less detectable by the AVs that scan the processes after they start.

#### Atom Bombing *(Use of Global Atom Tables for injecting code)*
- Storage of the shellcode in a global atom table (```GlobalAddAtom```).
- Execution of the code via ```NtUserMessageCall```.
- Is it contouring the monitoring of standard API calls.

# Persistence and Task Masking Techniques
#### Process Injection into a Legitimate Process
- Injection of malicious code in ```explorer.exe```, ```svchost.exe``` to hide the execution.
- Difficult detection by conventional antiviruses.

#### Thread Execution Hijacking
- Diversion of an existing thread via ```SuspendThread```, change in context (```SetThreadContext```), then ```ResumeThread```.
- Enables code to be injected without creating a new process.

#### Code Running in Legitimate Services
- Execution of malicious commands in ```msiexec.exe```, ```rundll32.exe``` (LOLBins).
- Example in PowerShell:
```
rundll32.exe C:\chemin\vers\dll.dll, EntryPoint
```

#### Register Keys and Register Keys
- Use of ```Alternate Data Streams (ADS)``` to hide files:
```
echo "Malicious Code" > normal.txt:hidden.txt
```
- Masking malicious registry keys with ```RegHide```.

#### Use of Signed Binaries for Execution (LOLBins)
- Execution of malicious scripts via Microsoft-signed applications (```mshta.exe```, ```wscript.exe```).
- Allows you to bypass the Whitelisting Application (AWL).

#### Operation of objects COM
- COM hijacking, execution via ```ShellWindows```, ```Wscript.Shell```.

#### Hijacking of Shortcuts
- Enforcement of code via files ```.lnk```.
















