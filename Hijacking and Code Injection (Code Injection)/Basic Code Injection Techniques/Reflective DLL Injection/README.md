# Reflective DLL Injection
***Reflective DLL Injection** is a **stealthy** technique used to **inject and execute a DLL (Dynamic Link Library) entirely from memory**, without using the standard Windows loader.
This method is widely used by malware, red teamers, and penetration testers to bypass security measures such as **antivirus (AV) and endpoint detection and response (EDR) systems**.*

## Why Use Reflective DLL Injection?

- **Fileless Execution** – No need to drop the DLL on disk, making detection harder.
- **Bypasses Security Solutions** – Since the DLL is loaded in memory, it can bypass AV and EDR.
- **Custom Loader Control** – The attacker manually handles the DLL loading process, avoiding API hooks.
- **Evades Forensic Analysis** – No traces are left in the Windows DLL load logs.
- **Used in Advanced Attacks** – This technique is common in malware, rootkits, and C2 frameworks.

# How Reflective DLL Injection Works?
*Unlike standard DLL loading with ```LoadLibrary()```, where the OS handles everything, **Reflective DLL Injection follows a custom approach**:*

### 1. Allocate Memory for the DLL
  - The injector allocates memory inside the target process using ```VirtualAllocEx()``` or ```NtAllocateVirtualMemory()```.

### 2. Copy the DLL into Memory
  - The entire DLL file is manually written into the allocated memory using ```WriteProcessMemory()```.

### 3. Locate and Resolve DLL Import Table
  - Since the Windows loader is not used, the DLL must resolve its **import table** and find required APIs manually.

### 4. Adjust Memory Relocations
  - If the DLL is loaded at a different base address than expected, **relocations are fixed manually** using the relocation table.

### 5. Execute the DLL’s Entry Point (Reflectively)
  - Instead of Windows calling ```DllMain()```, the **DLL finds and executes its own entry point**.

## Reflective DLL Injection Attack Diagram
*Here’s a visual representation of the attack:*
```
┌──────────────────────────┐
│ 1. Find Target Process   │  
│ (e.g., explorer.exe)     │  
└───────────┬──────────────┘  
            │  
            ▼  
┌──────────────────────────┐  
│ 2. Allocate Memory       │  
│ (VirtualAllocEx in Proc) │  
└───────────┬──────────────┘  
            │  
            ▼  
┌──────────────────────────┐  
│ 3. Write DLL to Memory   │  
│ (WriteProcessMemory)     │  
└───────────┬──────────────┘  
            │  
            ▼  
┌──────────────────────────┐  
│ 4. Resolve Imports & Fix │  
│ Relocations (Manually)   │  
└───────────┬──────────────┘  
            │  
            ▼  
┌──────────────────────────┐  
│ 5. Locate DllMain()      │  
│ (Find Entry Point)       │  
└───────────┬──────────────┘  
            │  
            ▼  
┌──────────────────────────┐  
│ 6. Create Remote Thread  │  
│ (Execute DllMain)        │  
└───────────┬──────────────┘  
            │  
            ▼  
┌──────────────────────────┐  
│ 7. Malicious Code Runs   │  
│ (Inside Target Process)  │  
└──────────────────────────┘  
```
# Detection and Defense Against Reflective DLL Injection
## How to Reflective DLL Injection?
- **Memory Scanning** – Security tools scan for suspicious DLLs that are not mapped from disk.
- **API Monitoring** – Hooking functions like ```VirtualAllocEx()```, ```WriteProcessMemory()```, and ```CreateRemoteThread()```.
- **Unbacked Memory Regions** – DLLs normally have a backing file on disk. Injected DLLs do not.
- **Kernel-Based Detection** – ETW (Event Tracing for Windows) can detect anomalies in process execution.

## Defense Strategies
- **Block Malicious API Calls** – Restrict ```WriteProcessMemory()``` and ```CreateRemoteThread()``` in userland.
- **Enable Memory Integrity Protection** – Prevent unsigned code execution via Windows Defender Exploit Guard.
- **Use Kernel-Based Monitoring** – Solutions like Microsoft Defender ATP can detect process injection techniques.
- **Behavioral Analysis** – Detect anomalies such as unauthorized DLL loading inside legitimate processes.
