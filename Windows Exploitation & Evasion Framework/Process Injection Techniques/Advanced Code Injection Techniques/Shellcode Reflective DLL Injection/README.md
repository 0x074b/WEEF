# Shellcode Reflective DLL Injection
***Shellcode Reflective DLL Injection** is a stealthy and advanced code injection technique that combines **shellcode execution** with **Reflective DLL Injection**.
This method allows an attacker to inject and execute a malicious **Dynamic Link Library (DLL)** inside a target process using **only shellcode**, without relying on traditional API calls like ```LoadLibrary```.*

*The key advantage of this technique is that it enables **fileless** execution, making it harder for security solutions like antivirus (AV) and Endpoint Detection and Response (EDR) to detect and block the attack.*

## Understanding the Key Components
*Before diving into the attack, let’s break down the components:*

- **Shellcode** – A small piece of malicious machine code that is typically injected into a process's memory and executed. It can be delivered in different ways, including remote exploits, process injection, or memory corruption.
- **Reflective DLL Injection** – A technique where a DLL loads itself into a process without using ```LoadLibrary```, making it stealthy and difficult to detect.
- **Shellcode Reflective DLL Injection** – A combination of both techniques where the shellcode contains a Reflective Loader that loads a DLL into memory and executes it, all without touching disk or using Windows API calls.

## Why Use Shellcode Reflective DLL Injection?
*Attackers favor this technique because it:*

- **Bypasses security solutions** – Avoids detection from traditional AVs and EDR by not writing a file to disk.
- **Evades API monitoring** – Doesn't use ```LoadLibrary``` or other monitored API functions.
- **Executes entirely in memory** – The attack is **fileless**, meaning there is no trace left on disk.
- **Maintains persistence** – Can be used to inject backdoors, keyloggers, or establish remote access in a system.

# How Shellcode Reflective DLL Injection Works
*The attack follows these key steps:*

### 1. Crafting the Reflective DLL – The attacker creates a malicious DLL that includes:
  - A **Reflective Loader** (custom code that loads the DLL into memory).
  - The **malicious payload** (e.g., a reverse shell, keylogger, or other malware).

### 2. Generating the Shellcode – The attacker extracts the Reflective Loader and payload from the DLL and encodes it into raw shellcode.

### 3. Injecting the Shellcode – The attacker injects the shellcode into a target process using a method such as:
  - **Remote process injection** (```WriteProcessMemory``` + ```CreateRemoteThread```).
  - **Exploiting a vulnerability** (e.g., buffer overflow or RCE).
  - **Thread hijacking** (modifying execution of an existing thread).

### 4. Executing the Shellcode – Once injected, the shellcode:
  - Allocates memory for the DLL.
  - Writes the DLL contents into memory.
  - Calls the **Reflective Loader**, which loads the DLL and executes it within the process.

### 5. Malicious Payload Execution – The DLL runs inside the target process, executing the attacker’s code stealthily.

# Diagram of Shellcode Reflective DLL Injection
```
        ┌───────────────────────────────────────┐
        │ Attacker                              │
        │ (Generates Malicious DLL & Shellcode) │
        └───────────────┬───────────────────────┘
                        │
                        ▼
        ┌─────────────────────────────────────────────┐
        │ Target Process (Legitimate Application)     │
        │                                             │
        │  [1] Allocate Memory for Shellcode          │◄─── VirtualAllocEx()
        │  [2] Write Shellcode into Process Memory    │◄─── WriteProcessMemory()
        │  [3] Execute Shellcode via Remote Thread    │◄─── CreateRemoteThread()
        │                                             │
        │ ─────────────────────────────────────────── │
        │                                             │
        │ Shellcode Execution:                        │
        │                                             │
        │  [4] Allocate Memory for DLL in Process     │◄─── VirtualAlloc()
        │  [5] Copy DLL Contents into Memory          │◄─── memcpy()
        │  [6] Resolve Imports & Base Address         │◄─── Manually Parse PE Headers
        │  [7] Execute DLL Main Function              │◄─── Call Reflective Loader
        │                                             │
        │ ─────────────────────────────────────────── │
        │                                             │
        │ Malicious Payload Execution:                │
        │                                             │
        │  [8] Establish Reverse Shell / Keylogger    │◄─── Payload Execution
        │  [9] Inject into Another Process (Optional) │
        │ [10] Persist on System (Optional)           │
        └─────────────────────────────────────────────┘
```
## Example Attack Flow
### 1. Creating a Reflective DLL
*The attacker writes a Reflective DLL that:*

- Includes a ```DllMain``` function with malicious payload (e.g., reverse shell).
- Implements a **Reflective Loader** that:
  - Allocates memory.
  - Resolves imports dynamically.
  - Executes the DLL from memory.

*Example C++ Code for Reflective Loader:*
```
extern "C" __declspec(dllexport) void ReflectiveLoader() {
    // Code to load the DLL into memory and resolve dependencies
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        MessageBox(NULL, "Malicious DLL Loaded!", "Warning", MB_OK);
    }
    return TRUE;
}
```
### 2. Extracting Shellcode from DLL
*The DLL is then converted into **raw shellcode** using a tool like **Donut** or a custom script:*
```
donut -f shellcode.dll -o shellcode.bin
```

### 3. Injecting the Shellcode
*The attacker writes the shellcode into a process’s memory and executes it. Example C++ code:*
```
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, pRemoteMemory, shellcode, shellcodeSize, NULL);
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteMemory, NULL, 0, NULL);
```

### 4. Shellcode Executes and Loads the DLL
*Once executed, the **Reflective Loader** inside the shellcode:*

- **Allocates memory** for the DLL.
- **Loads the DLL into memory** without calling ```LoadLibrary```.
- **Executes the malicious payload**.

### 5. Payload Execution
*Once the DLL is loaded, it can:*

- Open a **reverse shell** to connect back to the attacker.
- **Inject itself into another process** for persistence.
- **Steal credentials or exfiltrate data**.

# Defenses Against Shellcode Reflective DLL Injection
*To mitigate this attack, security teams can use several defensive techniques:*

- Enforce Code Integrity Policies
  - Enable **Secure Boot** and **Windows Defender Application Control (WDAC)** to block unsigned DLLs from executing.
  - Use **Microsoft Defender Attack Surface Reduction (ASR)** rules to prevent **code injection**.

- Monitor API Calls & Process Behavior
  - Use **EDR solutions** to detect:
    - ```VirtualAllocEx```
    - ```WriteProcessMemory```
    - ```CreateRemoteThread```
    - Unusual process injection behavior.

- Implement Memory Protection Mechanisms
  - Enable **Data Execution Prevention (DEP)** and **Control Flow Guard (CFG)** to prevent shellcode execution.
  - Use **Address Space Layout Randomization (ASLR)** to randomize memory locations, making it harder to inject shellcode.

- Use Behavior-Based Threat Detection
  - Detect suspicious **memory allocation patterns**.
  - Monitor **network traffic** for unexpected outbound connections (e.g., reverse shell activity).
