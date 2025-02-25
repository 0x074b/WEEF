# Process Hollowing
***Process Hollowing** is a code injection technique where an attacker starts a legitimate process in a **suspended state**, empties its memory, and replaces it with malicious code before resuming execution.
This technique is commonly used to **hide malware** by making it appear as a trusted process.*

## Why Use Process Hollowing?

- **Bypass antivirus and EDR detection** by running inside a trusted process.
- **Hide malware execution** behind a legitimate Windows process.
- **Gain elevated privileges** by injecting into a high-privilege process.
- **Evade behavioral monitoring** by executing within a system process.

> [!NOTE]
> **Process Hollowing** is more **stealthy** than classic DLL injection but requires **higher privileges**.

# How Process Hollowing Works
*Process Hollowing follows these main steps:*

1. **Create a Suspended Process** – A legitimate process (e.g., ```svchost.exe```) is created in a **suspended state** using ```CreateProcess``` with ```CREATE_SUSPENDED``` flag.
2. **Unmap the Process Memory** – The original memory of the target process is erased using ```ZwUnmapViewOfSection```.
3. **Allocate New Memory** – The attacker allocates memory in the process using ```VirtualAllocEx```.
4. **Inject Malicious Code** – The malicious executable is written into the allocated memory using ```WriteProcessMemory```.
5. **Set Execution Context** – The Entry Point of the process is modified with ```SetThreadContext``` to point to the malicious code.
6. **Resume Execution** – The suspended process is resumed using ```ResumeThread```, now running the attacker's payload.

# Process Hollowing Attack Diagram
*Here’s a visual representation of the attack:*
```
┌────────────────────┐
│ 1. Create Process  │  
│ (Suspended)        │  
│ e.g., svchost.exe  │  
└───────┬────────────┘  
        │  
        ▼  
┌────────────────────┐  
│ 2. Unmap Memory    │  
│ (Erase Legit Code) │  
└───────┬────────────┘  
        │  
        ▼  
┌────────────────────┐  
│ 3. Allocate Memory │  
│ (For Malware Code) │  
└───────┬────────────┘  
        │  
        ▼  
┌────────────────────┐  
│ 4. Inject Code     │  
│ (Write Malware)    │  
└───────┬────────────┘  
        │  
        ▼  
┌────────────────────┐  
│ 5. Modify Entry    │  
│ Point (SetThread)  │  
└───────┬────────────┘  
        │  
        ▼  
┌────────────────────┐  
│ 6. Resume Process  │  
│ (Now Running Mal.) │  
└────────────────────┘  
```

# Detection and Defense Against Process Hollowing
## How to Detect Process Hollowing?
- **Monitor Suspended Processes** – Detect processes that remain in a suspended state for too long.
- **Check Memory Inconsistencies** – If a process’s memory differs from its original file on disk, it may be hollowed.
- **Detect Unmapped Sections** – Tools like **Process Hacker** can show if a process has unmapped memory regions.
- **Monitor API Calls** – Calls like ```ZwUnmapViewOfSection```, ```WriteProcessMemory```, and ```SetThreadContext``` indicate possible Process Hollowing.

## Defense Techniques

- **Enable Windows Defender’s Attack Surface Reduction (ASR)** – Helps prevent suspicious memory modifications.
- **Use Behavior-Based Detection** – Traditional signature-based AVs may not detect Process Hollowing, but **EDR solutions** can monitor behavior.
- **Restrict Process Creation Policies** – Limit which applications can spawn new processes.
