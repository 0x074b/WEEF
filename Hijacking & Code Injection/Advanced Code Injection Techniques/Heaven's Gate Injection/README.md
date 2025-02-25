# Heaven’s Gate Injection
***Heaven’s Gate Injection** is a stealthy **code injection** technique that allows **32-bit processes running on a 64-bit Windows system (WOW64) to execute 64-bit shellcode**.
This method is used by malware and attackers to bypass **user-mode hooks**, **security monitoring**, **and detection tools**, as many security solutions focus only on **32-bit API calls within WOW64 processes** and do not monitor **64-bit execution within the same process**.*

## Why Use Heaven’s Gate Injection?

- **Bypasses API Hooking** – Most security tools hook **32-bit API calls** in WOW64 processes but fail to monitor **64-bit execution**.
- **Stealthy Execution** – Hides execution from EDRs and AVs that only analyze 32-bit operations.
- **Expands Attack Surface** – Grants access to **64-bit system calls**, which may have fewer restrictions than their 32-bit equivalents.
- **Evasion of User-mode Hooks** – Security solutions often place hooks on ```Nt*``` API calls in ```ntdll.dll```, but this technique **switches to 64-bit mode** to execute unmonitored.

# How Heaven’s Gate Injection Works?

*Windows-on-Windows 64-bit (WOW64) allows **32-bit applications to run on 64-bit Windows**.
However, these applications **can switch to 64-bit mode manually**, which is what Heaven’s Gate exploits.*

*Normally, **32-bit processes** use ```wow64.dll``` and ```ntdll.dll``` (32-bit) to perform system calls.
Heaven’s Gate **bypasses** ```wow64.dll``` and manually jumps into **64-bit** ```ntdll.dll```, avoiding monitoring hooks.*

### 1. Identifying a 32-bit WOW64 Process

- The attacker chooses a **32-bit application running on a 64-bit system** (e.g., ```explorer.exe``` or ```cmd.exe```).
- Windows **emulates 32-bit execution** inside a WOW64 process, which can secretly switch to 64-bit mode.

### 2. Switching from 32-bit to 64-bit Mode

- The attacker **uses inline assembly** or low-level ```RIP``` manipulation to switch execution mode:
```
mov eax, 0x33       ; 0x33 = 32-bit code segment
push rax
retf                ; Far return to switch to 64-bit mode

mov eax, 0x23       ; 0x23 = 64-bit code segment
push rax
retf                ; Return to 64-bit execution
```

### 3. Executing 64-bit Shellcode

- Once in **64-bit mode**, the attacker **resolves 64-bit system calls directly** in ```ntdll.dll```.
- The process **bypasses API hooks** set in the 32-bit execution layer.
- Attackers can now execute **64-bit malware payloads**, inject code, or manipulate memory without detection.

# Diagram of Heaven’s Gate Injection
```
        ┌─────────────────────────────┐
        │ Attacker (Malicious Code)   │
        └───────────┬─────────────────┘
                    │
                    ▼
        ┌──────────────────────────────┐
        │ WOW64 32-bit Mode            │
        │ - Uses wow64.dll & ntdll.dll │
        │ - Security Hooks Active      │
        └───────────┬──────────────────┘
                    │
                    ▼
        ┌─────────────────────────────┐
        │ Switch to 64-bit Mode       │
        │ - Executes 64-bit Shellcode │
        │ - Bypasses Security Hooks   │
        └───────────┬─────────────────┘
                    │
                    ▼
        ┌───────────────────────────────┐
        │ Kernel Mode Execution         │
        │ - 64-bit Syscalls Unmonitored │
        └───────────────────────────────┘
```

# Defense Against Heaven’s Gate Injection
## Behavioral Detection
- **Monitor WOW64 Mode Transitions** – Security tools can detect if a process **switches from 32-bit to 64-bit execution**.
- **Track Syscalls in 64-bit Mode** – Identify processes that make unexpected 64-bit system calls from a WOW64 environment.
- **Detect Unusual Code Execution in 64-bit Space** – Many WOW64 processes never execute 64-bit shellcode.

## Mitigation Strategies
- **Use EDR Solutions with Kernel Monitoring** – Security tools should track both **32-bit and 64-bit system calls** inside WOW64 processes.
- **Restrict Execution of Untrusted 32-bit Applications** – Attackers rely on **legacy 32-bit apps** to exploit Heaven’s Gate.
- **Enable Process Integrity Enforcement** – Prevent unsigned or modified processes from executing.
