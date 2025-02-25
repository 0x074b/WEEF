# DLL Injection
***DLL Injection** is a technique used to execute arbitrary code within the address space of a legitimate process by loading a malicious **Dynamic Link Library (DLL)**.
Attackers commonly use this method to **hide their presence, escalate privileges**, or **execute malicious** code within a trusted process.*

##  What is a DLL?

*A **DLL (Dynamic Link Library)** is a file containing executable code that multiple programs can use simultaneously.
It helps **reduce redundancy** and **share functionalities** across applications in Windows.*

## Why Inject a DLL?
- **Hijack a legitimate process** *to run malicious code.*
- **Bypass security mechanisms** *(e.g., antivirus or EDR).*
- **Gain persistence** *by injecting code into system processes.*
- **Steal sensitive information** *by hooking into a process (e.g., keylogging, password theft).*
- **Modify application behavior** *(e.g., cheat in games, manipulate software functions).*

# How DLL Injection Works
*DLL Injection works by forcing a target process to load an attacker-controlled DLL.*
*The main steps include:*

1. **Finding the target process** – The attacker identifies the process to inject into.
2. **Allocating memory inside the process** – The injector reserves space in the target’s memory.
3. **Writing the DLL path into memory** – The injector places the malicious DLL’s path inside the allocated space.
4. **Creating a remote thread** – The injector forces the process to execute ```LoadLibrary``` to load the DLL.
5. **Executing malicious code** – Once loaded, the DLL executes inside the process.

## Diagram of a DLL Injection Attack
*(A remote process injects a malicious DLL into a target process.)*
```
┌──────────────┐
│ Attacker     │
│ (Injector)   │
└────┬─────────┘
     │
     ▼
┌────────────────────┐
│ Target Process     │
│ (Legitimate App)   │
│                    │
│ - Allocated Memory │◄─── [1] Memory Allocation
│ - DLL Path Stored  │◄─── [2] Write DLL Path
│ - LoadLibrary Call │◄─── [3] Create Remote Thread
│ - Malicious Code   │◄─── [4] DLL Execution
└────────────────────┘
```

# Defense Against DLL Injection
*To protect against DLL injection attacks:*

- **Use Secure Boot & Code Integrity Policies** – Prevent unsigned DLLs from loading.
- **Enable Process Mitigation Policies** – Use ```SetProcessMitigationPolicy``` to block remote thread creation.
- **Restrict DLL Loading Locations** – Limit where applications can load DLLs from.
- **Monitor API Calls** – Watch for ```WriteProcessMemory```, ```CreateRemoteThread```, and ```LoadLibrary```.
- **Use EDR & Behavioral Detection** – Detect anomalies like unusual process injections.
