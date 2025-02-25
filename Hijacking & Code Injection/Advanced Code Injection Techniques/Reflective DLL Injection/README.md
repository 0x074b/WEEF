# Reflective DLL Injection
***Reflective DLL Injection** is a technique where an attacker injects a **Dynamic Link Library (DLL)** into the address space of a target process without the need to use conventional loading mechanisms such as ```LoadLibrary```.
The key characteristic of reflective DLL injection is that the DLL contains code capable of **loading itself** into memory.
This makes it particularly stealthy, as the injected DLL doesn’t rely on external functions to load, bypassing many traditional detection mechanisms.*

## What is a Reflective DLL?
*A **Reflective DLL** is a specially crafted Dynamic Link Library (DLL) that is able to load itself into memory and execute its code without relying on external functions like ```LoadLibrary``` or ```SetWindowsHookEx```.
The reflection process is generally implemented using the **Reflective Loader**, a custom piece of code that can read and execute the contents of the DLL from memory, essentially making the DLL "reflect" its own execution.*

*The **Reflective Loader** typically contains a function that:*

1. Loads the DLL from memory.
2. Resolves the DLL's imports.
3. Transfers control to the DLL’s entry point.

*Reflective DLL Injection allows attackers to inject code into a target process while minimizing the chance of detection by traditional security mechanisms.*

## Why Use Reflective DLL Injection?
*Attackers may use Reflective DLL Injection for several reasons, including:*

- **Bypassing Security Defenses** – Reflective DLL injection helps bypass security mechanisms such as antivirus software or Endpoint Detection and Response (EDR) systems, which are designed to detect DLL injection through common APIs like ```LoadLibrary```.
- **Stealth** – Since the reflective DLL loads itself into memory without the need for the standard API calls that are typically monitored, it is harder for security tools to detect.
- **Execution in Context** – Reflective DLL injection allows attackers to execute malicious code in the context of a legitimate process, often helping them evade detection and increasing the chances of successful exploitation.
- **Persistence** – Once injected, the reflective DLL may execute any malicious payload, such as a reverse shell or backdoor, and maintain control over the target process.

# How Reflective DLL Injection Works
*The process of Reflective DLL Injection typically involves the following steps:*

1. **Prepare the Reflective DLL** – The attacker creates a reflective DLL, which includes the malicious payload and the reflective loader code. The DLL is compiled in such a way that it can load itself when injected into memory.
2. **Identify the Target Process** – The attacker identifies a target process that they want to inject the reflective DLL into. This could be a system process, a vulnerable application, or a process running with elevated privileges.
3. **Inject the Reflective DLL** – The attacker injects the reflective DLL into the target process. This can be done by using techniques like **CreateRemoteThread**, **WriteProcessMemory**, or other methods to write the DLL’s memory contents into the target process’s address space.
4. **Load the DLL into Memory** – The reflective loader inside the DLL handles the process of loading the DLL from memory. Once injected, the loader code will read the DLL's data and resolve the imports, effectively loading it into the target process.
5. **Execute the Payload** – Once the reflective DLL is loaded into memory, it transfers control to the entry point of the DLL (usually ```DllMain``` or a custom entry function). This allows the attacker’s payload (e.g., reverse shell, keylogger, or malware) to execute inside the context of the target process.
6. **Optionally** – Maintain Persistence: The reflective DLL may attempt to maintain persistence on the system, execute additional attacks, or provide ongoing access to the attacker.

# Diagram of Reflective DLL Injection Attack
*Here’s a simplified diagram illustrating the Reflective DLL Injection attack flow:*
```
(Attacker injects reflective DLL into the target process)

┌──────────────┐
│ Attacker     │
│ (Reflective  │
│ DLL Payload) │
└──────┬───────┘
       │
       ▼
┌──────────────────────────┐
│ Target Process           │
│ (Legitimate Application) │
│                          │
│ - Allocate Memory        │◄─── [1] Allocate Memory for DLL
│ - Inject Reflective DLL  │◄─── [2] Inject Reflective DLL
│ - Load DLL into Memory   │◄─── [3] Self-Loading via Reflective Loader
│ - Execute Payload        │◄─── [4] Execute Malicious Code
└──────────────────────────┘
```
## Advantages of Reflective DLL Injection

- **Stealth** – Since reflective DLL injection avoids standard Windows APIs like ```LoadLibrary```, it can evade traditional detection mechanisms that monitor those APIs for suspicious activity.
- **Reduced Detection** – Security software often focuses on detecting suspicious behavior related to ```LoadLibrary``` or other standard DLL injection techniques, but reflective DLLs can load without triggering these detections.
- **Flexible Payloads** – Reflective DLL injection allows attackers to inject any type of payload into the process, whether it be for espionage (e.g., keylogging), persistence, or gaining remote access (e.g., reverse shell).
- **Bypass Antivirus** – By using a reflective DLL, attackers can bypass antivirus programs that focus on detecting files loaded from disk, as the DLL is injected directly into memory.

# Defense Against Reflective DLL Injection
*To protect against Reflective DLL Injection attacks, several defensive techniques can be employed:*

- **Code Integrity Policies** – Use Windows Code Integrity and Secure Boot policies to prevent unsigned code from being executed in sensitive processes, making it harder for malicious DLLs to run.
- **Memory Protection Mechanisms** – Enable Data Execution Prevention (DEP) and Address Space Layout Randomization (ASLR) to make it more difficult for attackers to predict memory locations and execute injected code.
- **Process Mitigation** – Use process mitigation features such as Anti-Dependant DLLs, Control Flow Guard (CFG), and SetProcessMitigationPolicy to block common injection techniques, including reflective DLL injection.
- **Behavioral Analysis** – Implement Endpoint Detection and Response (EDR) tools that focus on the behavior of processes rather than just file signatures. These tools can detect abnormal process behavior, such as reflective loading of DLLs.
- **Monitor API Calls** – Monitor calls to Windows API functions such as CreateRemoteThread, WriteProcessMemory, and other functions commonly used in DLL injection attacks. Any suspicious activity can be flagged for further analysis.
- **Restrict DLL Loading Locations** – Configure applications to load DLLs only from trusted directories, preventing untrusted or malicious DLLs from being injected.
