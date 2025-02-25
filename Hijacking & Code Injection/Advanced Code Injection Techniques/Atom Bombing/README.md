# Atom Bombing
***Atom Bombing** is a stealthy **code injection** technique that abuses **Windows Atom Tables** to execute malicious code inside another process.
This method does not rely on traditional API calls like ```WriteProcessMemory()``` or ```CreateRemoteThread()```, making it harder for security tools (AV/EDR) to detect.*

*The technique was first publicly documented by **Ensilo (now Fortinet)** in 2016 and remains relevant for **bypassing security solutions** and executing **malicious payloads without direct memory writing**.*

## Why Use Atom Bombing?

- **Bypass Security Monitoring** – Avoids detection by EDR solutions that monitor ```WriteProcessMemory()```.
- **Execute Code in Remote Processes** – Can run malicious payloads inside a legitimate process.
- **Avoid Signature-Based Detection** – Atom Tables are a legitimate Windows feature, not inherently malicious.
- **Persistence & Stealth** – The injected payload can persist across sessions and evade forensic tools.

# How Atom Bombing Works?
Atom Bombing uses **Windows Global Atom Tables**, which store small pieces of data that multiple processes can access.
Attackers exploit this feature by **storing malicious shellcode in the Atom Table**, then **forcing another process to retrieve and execute it**.

### 1. Store Malicious Payload in the Atom Table

- The attacker writes malicious shellcode into a **Global Atom Table** entry using ```GlobalAddAtom()```.
- The payload is stored **without directly writing to another process’s memory**, making it stealthy.

```ATOM atom = GlobalAddAtomA(maliciousPayload);```

### 2. Find the Target Process

- The attacker identifies a **legitimate process** (e.g., ```explorer.exe```) to execute the malicious code.
- The target process is chosen to avoid suspicion and maintain stealth.

```HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);```

### 3. Retrieve the Malicious Payload in the Target Process

- The Atom Table is **shared between processes**, so the attacker forces the target process to **retrieve the malicious payload** via ```GlobalGetAtomName()```.

```
char retrievedPayload[256];
GlobalGetAtomNameA(atom, retrievedPayload, sizeof(retrievedPayload));
```

### 4. Execute the Payload Using Asynchronous Procedure Calls (APC)

- The attacker uses **APC Injection** to queue a function call in the target process’s thread, ensuring the payload gets executed.
- ```NtQueueApcThread()``` is used to **invoke the shellcode**.

```NtQueueApcThread(hThread, (PVOID)retrievedPayload, NULL, NULL, NULL);```

# Diagram of Atom Bombing Attack
```
        ┌─────────────────────────────┐
        │  Attacker Process           │
        │  (Stores Malicious Code)    │
        └───────────┬─────────────────┘
                    │
                    ▼
        ┌─────────────────────────────┐
        │  Windows Global Atom Table  │
        │  [1] Store Shellcode        │◄─── GlobalAddAtomA()
        │  [2] Retrieve in Target     │◄─── GlobalGetAtomNameA()
        └───────────┬─────────────────┘
                    │
                    ▼
        ┌─────────────────────────────┐
        │  Target Process             │
        │  (e.g., explorer.exe)       │
        │  [3] Retrieve Atom Content  │
        │  [4] Execute via APC        │◄─── NtQueueApcThread()
        └─────────────────────────────┘
```

# Defense Against Atom Bombing
*Although Atom Bombing is stealthy, defensive measures exist:*

## Behavioral Detection

- **Monitor Atom Table modifications** – Large or unusual data stored in the Atom Table could indicate injection attempts.
- **Track** ```GlobalAddAtomA()``` **calls** – If a process repeatedly adds large binary data, it may be suspicious.
- **Detect abnormal** ```NtQueueApcThread()``` **usage** – Unexpected APC calls into non-standard execution flows should raise alerts.

 ## Mitigation Strategies

- **Restrict Atom Table Access** – Limit which processes can interact with Global Atom Tables.
- **Process Integrity Checks** – Ensure critical processes are not executing unexpected code.
- **EDR Solutions with Behavioral Analysis** – Look for **combined behaviors** (Atom Table writes + APC execution).
