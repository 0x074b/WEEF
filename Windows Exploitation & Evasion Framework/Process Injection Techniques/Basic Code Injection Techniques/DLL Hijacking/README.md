# DLL Hijacking
***DLL Hijacking** is a technique where an attacker exploits the search mechanism used by a program to load **Dynamic Link Libraries (DLLs)** into memory.
The attacker places a malicious DLL in a location where the program expects to find a legitimate one, thus causing the program to load the malicious DLL instead.
This attack is often used to **execute malicious code**, bypass security mechanisms, or manipulate the behavior of the targeted application.*

# Why Hijack a DLL?
*Attackers may hijack a DLL for various reasons, including:*

- **Running malicious code**: Execute harmful actions inside a legitimate process.
- **Bypassing security**: Evade antivirus or endpoint detection and response (EDR) systems.
- **Gaining persistence**: Maintain control over a system by injecting into trusted system processes.
- **Stealing information**: Use hooks to spy on activities like keystrokes or passwords.
- **Modifying application behavior**: Alter how programs function, such as cheating in video games or bypassing software restrictions.

# How DLL Hijacking Works
*The mechanism of **DLL Hijacking** is similar to **DLL Injection**, with the difference being that the attacker doesn't need to inject code directly into a process but rather tricks the application into loading a malicious DLL.*
*Here's how it works:*

1. **Identifying the Target Process** – The attacker identifies a legitimate program that loads a specific DLL.
2. **Placing a Malicious DLL** – The attacker places a malicious DLL in a directory where the target program searches for DLLs (e.g., the application's current working directory or a directory that is part of the system's PATH).
3. **Hijacking the DLL Load Process** – When the legitimate program attempts to load the DLL, it ends up loading the attacker-controlled one instead, since the malicious DLL is found first in the search path.
4. **Execution of Malicious Code** – Once the malicious DLL is loaded, the attacker can execute any code within the context of the legitimate program.

# Diagram of a DLL Hijacking Attack
*Here’s a step-by-step diagram illustrating how a DLL Hijacking attack unfolds:*
```
(Attacker places a malicious DLL in the search path)

┌─────────────────┐
│ Attacker        │
│ (Malicious DLL) │
└──────┬──────────┘
       │
       ▼
┌──────────────────────────┐
│ Target Process           │
│ (Legitimate Application) │
│                          │
│ - Searches for DLL       │◄─── [1] Searching for DLL
│ - Malicious DLL found    │◄─── [2] DLL Hijacking
│ - Malicious Code Loaded  │◄─── [3] Executing Malicious Code
└──────────────────────────┘
```

# Defense Against DLL Hijacking

*To mitigate the risk of DLL Hijacking, consider the following defensive measures:*

- **Use Secure Boot & Code Integrity** – Enforce that only signed, trusted DLLs can be loaded by applications. This prevents malicious DLLs from being executed in the first place.
- **Enforce Process Mitigation Policies** – Policies such as ```SetProcessMitigationPolicy``` can prevent remote threads or malicious DLLs from being injected into processes.
- **Restrict DLL Loading Locations** – Limit the directories from which applications are allowed to load DLLs. This reduces the risk of loading DLLs from untrusted locations.
- **Monitor API Calls** – Keep an eye on critical system calls like ```WriteProcessMemory```, ```CreateRemoteThread```, and ```LoadLibrary``` to detect unusual behavior associated with DLL loading.
- **Use EDR & Behavioral Detection** – Endpoint Detection and Response (EDR) systems can be used to identify abnormal DLL loading behavior or suspicious process injections.
