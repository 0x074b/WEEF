# Thread Execution Hijacking
***Thread Execution Hijacking** is a stealthy **code injection technique** that allows an attacker to take control of an existing thread within a legitimate process. 
Instead of creating a new thread (which may be detected by security tools), the attacker **modifies an already running thread** to execute malicious code.*

*This technique is commonly used to **bypass security measures** such as antivirus (AV), Endpoint Detection & Response (EDR), and behavioral analysis tools.*

## Why Use Thread Execution Hijacking?
- **Avoids creating new threads** – Less suspicious than starting a new process or thread.
- **Uses legitimate processes** – The attack happens inside a trusted process, reducing detection chances.
- **Does not require process replacement** – Unlike **Process Hollowing**, the original process remains unchanged.
- **Difficult to detect** – Security tools may struggle to differentiate between a normal and hijacked thread.

> [!NOTE]
> **Thread Execution Hijacking** is more **subtle** than traditional injection methods because it **does not require** creating a **new thread or replacing an entire process**.

# How Thread Execution Hijacking Works

### 1. Find a Target Process and Thread
  - The attacker identifies a **running process** and an **active thread** inside it.
  - The target process is usually **a legitimate system or user process** (e.g., ```explorer.exe```).
  - The attacker ensures the chosen thread is in a **suspended or waiting state** to modify it easily.

### 2. Suspend the Thread
  - The attacker **suspends the selected thread** using the ```SuspendThread()``` API.
  - This ensures that the thread's execution is paused, preventing instability while injecting code.

### 3. Modify the Thread Context
  - The attacker retrieves the **thread’s execution context** using ```GetThreadContext()```.
  - The instruction pointer (EIP for 32-bit, RIP for 64-bit) is **modified to point to the attacker's malicious code**.
  - The attacker's code is either:
    - **Injected into the target process** via ```VirtualAllocEx()``` and ```WriteProcessMemory()```, or
    - **Executed from existing memory regions** to avoid detection.

### 4. Resume the Hijacked Thread
  - The attacker resumes the thread using ```ResumeThread()```.
  - The hijacked thread now **executes the attacker’s payload instead of its original instructions**.

# Thread Execution Hijacking Attack Diagram
*Here’s a step-by-step visual representation of how Thread Execution Hijacking works:*
```
┌─────────────────────────────────────────┐
│ 1. Find a Target Process & Thread       │  
│ Identify a process (e.g., explorer.exe) │  
│ Locate an active thread                 │  
└───────────┬─────────────────────────────┘  
            │  
            ▼  
┌──────────────────────────────────────┐  
│ 2. Suspend the Target Thread         │  
│ Use SuspendThread() API              │  
│ Pause execution for modification     │  
└───────────┬──────────────────────────┘  
            │  
            ▼  
┌────────────────────────────────────────────┐  
│ 3. Modify the Thread Context               │  
│ Use GetThreadContext() to retrieve EIP/RIP │  
│ Change the instruction pointer to malware  │  
│ Inject payload into memory if needed       │  
└───────────┬────────────────────────────────┘  
            │  
            ▼  
┌─────────────────────────────────────────┐  
│ 4. Resume the Hijacked Thread           │  
│ Use ResumeThread() API                  │  
│ The thread executes the attacker's code │  
└─────────────────────────────────────────┘  
```

# Detection and Defense Against Thread Execution Hijacking
## How to Detect Thread Execution Hijacking?

- **Monitor Suspicious API Calls** – Look for ```SuspendThread()```, ```GetThreadContext()```, ```SetThreadContext()```, ```ResumeThread()```.
- **Analyze Thread Context Changes** – Unusual changes in a thread's instruction pointer (EIP/RIP) can indicate hijacking.
- **Detect Memory Modifications** – If a thread suddenly starts executing code from an unusual memory region, it may be hijacked.
- **Behavioral Analysis** – If a thread in a normal process suddenly exhibits suspicious behavior, it might be compromised.

## Defense Techniques

- **Use Advanced EDR Solutions** – Traditional AV may fail; behavioral monitoring is required.
- **Restrict API Access** – Prevent non-administrative users from calling ```SuspendThread()``` and ```SetThreadContext()```.
- **Monitor Thread Execution Paths** – Ensure that executing threads follow normal execution paths.
- **Enable Security Logging** – Windows Event Logging can capture unusual thread modifications.
