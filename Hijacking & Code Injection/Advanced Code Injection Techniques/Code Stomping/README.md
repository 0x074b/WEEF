# Code Stomping Injection
***Code Stomping** is a **stealthy code injection technique** used by attackers to execute **malicious code while hiding it from memory analysis tools**.
Unlike traditional injection methods that allocate and execute new memory regions, Code Stomping **overwrites existing legitimate code sections with malicious payloads** while preventing detection by avoiding memory allocation flags that usually signal injected code.*

*This technique is widely used for **evasion**, **stealth**, and **persistence**, as security tools typically scan memory for suspicious regions marked as **executable** and **writable** (```RWX```), whereas Code Stomping modifies **legitimate** ```RX``` **(Read-Execute) regions**, making detection much harder.*

# Why Use Code Stomping?
- **Bypasses Memory Scanners** – Traditional scanning tools look for ```RWX``` sections, not ```RX``` sections.
- **Avoids Suspicious Memory Allocations** – No need for ```VirtualAlloc``` or ```VirtualProtect```, which are commonly monitored.
- **Hides Malicious Payloads** in Legitimate Processes – The malware overwrites valid code instead of allocating new memory.
- **Stealthy Execution** – The injected code runs from an **already trusted memory section**, reducing detection likelihood.

# How Code Stomping Works?
*Unlike traditional injection methods that allocate new memory (```VirtualAlloc```), Code Stomping:*

- **Overwrites legitimate code** inside an existing **Read-Execute (```RX```) memory region** (e.g., ```.text``` section of a DLL).
- **Executes malicious shellcode in-place**, so it appears as part of the original application.
- **Avoids common detection techniques** that scan for ```RWX``` or ```RWE``` (Read-Write-Execute) permissions.

### 1. Identifying a Target Process & Legitimate Code Section

- The attacker finds a process that contains a **trusted executable or DLL** (e.g., ```ntdll.dll```, ```kernel32.dll```).
- The goal is to overwrite part of its ```.text``` section without modifying memory protections.

### 2. Overwriting Code in an Executable Section

- The attacker locates an instruction sequence in an **executable section** (```RX```).
- Using ```WriteProcessMemory()```, the attacker **stomps over the existing code with malicious shellcode**.
- Example: Overwriting part of ```ntdll.dll``` with a payload that spawns a reverse shell.

```WriteProcessMemory(targetProcess, (LPVOID)targetAddress, maliciousPayload, payloadSize, NULL);```

- Since the memory remains **Read-Execute (```RX```)**, security tools **won't flag it as suspicious**.

### 3. Redirecting Execution to the Stomped Code

- The attacker **ensures execution flow reaches the modified section** using:
  - **Hooking existing functions** to redirect execution.
  - **Triggering an indirect jump or return instruction**.
  - **Hijacking an existing thread to execute the stomped code**.

### 4. Executing Malicious Payload & Restoring the Original Code

- The injected code **executes stealthily** within the legitimate process.
- Optionally, the attacker **restores the original bytes** after execution to prevent forensic analysis.

# Diagram of Code Stomping Injection
```
        ┌───────────────────────────┐
        │ Attacker (Malicious Code) │
        └───────────┬───────────────┘
                    │
                    ▼
        ┌──────────────────────────────┐
        │ Target Process Memory        │
        │ - Legitimate `.text` Section │
        │ - Read-Execute (`RX`)        │
        └───────────┬──────────────────┘
                    │
                    ▼
        ┌───────────────────────────┐
        │ Malicious Code Overwrites │◄── [1] WriteProcessMemory() 
        │ Legitimate Instructions   │
        └───────────┬───────────────┘
                    │
                    ▼
        ┌──────────────────────────────┐
        │ Execution Redirected         │◄── [2] Jump/Hook to Payload
        │ Stomped Code Runs Stealthily │
        └──────────────────────────────┘
```
# Defense Against Code Stomping
## Behavioral Detection
- **Monitor Calls to ```WriteProcessMemory()```** – Although the memory permissions remain ```RX```, unexpected writes to executable memory can be flagged.
- **Compare Memory Regions with Disk Executables** – Identify in-memory modifications by checking ```.text``` sections against their on-disk versions.
- **Detect Unusual Code Execution Flow** – Look for indirect jumps, function hooks, or modified return addresses leading to unusual memory regions.

## Mitigation Strategies

- **Enable Code Integrity Enforcement** – Protect system DLLs from unauthorized modifications.
- **Use Memory Scanning Tools** – Advanced security solutions can detect **modified code sections** inside trusted modules.
- **Monitor Thread Execution Context** – If a thread suddenly executes from a modified **RX** region, it may indicate Code Stomping.
