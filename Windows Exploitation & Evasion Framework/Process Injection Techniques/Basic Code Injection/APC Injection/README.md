# APC Injection
***APC Injection** (Asynchronous Procedure Call Injection) is a technique where an attacker injects malicious code into the address space of a target process by using **APCs**.
APCs are a type of function call in Windows that **allows code to be executed asynchronously** within the context of a thread in a process.
By exploiting this mechanism, attackers can execute arbitrary code in the context of a target process, bypassing many traditional security mechanisms.*

## What is an APC?
*An **Asynchronous Procedure Call (APC)** is a type of procedure call in Windows that allows a function to be executed in the context of a different thread.
APCs are queued to a thread's APC queue, and the thread processes these calls when it enters an alertable state (e.g., during a system call).
This mechanism allows functions to be executed asynchronously, without the calling thread having to wait for the execution to finish.*

*There are two main types of APCs:*
- **User-mode APCs** – These are queued in user-mode threads and can execute user-mode functions.
- **Kernel-mode APCs** – These are queued in kernel-mode threads and can execute kernel-mode functions.

## Why Use APC Injection?
*APC Injection is often used by attackers for various malicious purposes, such as:*

- **Running malicious code** – Execute arbitrary code within a legitimate process.
- **Bypassing security** – Inject code into system processes or applications to bypass security mechanisms like antivirus or EDR.
- **Gaining persistence** – Maintain control over a system by executing malicious code in high-privilege processes.
- **Elevating privileges** – Execute code in the context of a process running with elevated privileges, such as SYSTEM.
- **Hooking or modifying behavior** – Alter the behavior of a program by executing malicious or unauthorized actions.

# How APC Injection Works
*The APC Injection process involves several steps:*

1. **Identify the Target Process** – The attacker identifies a target process that they wish to inject code into. This can be a process with high privileges or one containing sensitive information.
2. **Allocate Memory in the Target Process** – The attacker allocates memory in the target process's address space to store the payload (the malicious code).
3. **Write the Malicious Code** – The attacker writes the payload (malicious code) into the allocated memory of the target process.
4. **Queue the APC** – The attacker uses Windows API functions, such as QueueUserAPC, to queue the payload into the target process's APC queue. This forces the target process’s thread to execute the malicious code when it enters an alertable state.
5. **Execution of Malicious Code** – Once the target thread processes the APC, the malicious code is executed within the context of the target process. The attacker can use this code to carry out their malicious activity.
6. **Optional: Repeat for Persistence** – The attacker may continue to inject APCs into different threads or processes to maintain persistence or escalate privileges.

# Diagram of APC Injection Attack
*Here’s a simplified diagram showing how an APC Injection works:*
```
(Attacker injects malicious APC into the target process)

┌─────────────────┐
│ Attacker        │
│ (Malicious APC) │
└──────┬──────────┘
       │
       ▼
┌──────────────────────────┐
│ Target Process           │
│ (Legitimate Application) │
│                          │
│ - Allocate Memory        │◄─── [1] Allocate Memory in Target
│ - Write Malicious Code   │◄─── [2] Write Code to Memory
│ - Queue APC              │◄─── [3] Queue APC to Thread
│ - Execute Malicious Code │◄─── [4] APC Execution
└──────────────────────────┘
```
## Example: Using APC Injection for Code Execution
*Let’s consider an example where an attacker uses APC Injection to execute malicious code within a high-privilege process:*

1. **Allocating Memory** – The attacker allocates memory in the target process (e.g., a system process or a browser) to store the malicious code.
2. **Writing the Payload** – The malicious payload, such as a reverse shell or keylogger, is written into the allocated memory.
3. **Queuing the APC** – Using QueueUserAPC, the attacker places the malicious code in the APC queue of the target thread.
4. **Execution** – The target thread eventually enters an alertable state (e.g., waiting for input or performing a system call), and the malicious code is executed in the target process’s context.
5. **Attacker Gains Control** – The malicious code executes with the same privileges as the target process, potentially allowing the attacker to escalate privileges, steal information, or manipulate the process.

# Defense Against APC Injection
*To mitigate the risks associated with APC Injection, several defensive strategies can be employed:*

- **Use of Process Mitigation Policies** – Windows provides process mitigation techniques that can block certain types of asynchronous calls, such as **SetThreadExecutionState** and **SetProcessMitigationPolicy**, to prevent malicious APC injections.
- **Monitoring Thread Behavior** – Monitor for suspicious thread behavior, such as unexpected use of ```QueueUserAPC``` or unusual API calls related to APCs. This can help detect and prevent APC-based attacks.
- **Control Thread Access** – Restrict access to thread-related APIs and limit the number of threads that can be created in a process. This reduces the chances of an attacker manipulating thread execution.
- **Integrity Checks** – Ensure that critical processes or system functions cannot be modified or injected with malicious code. This can be achieved using code integrity checks, signed binaries, and ensuring the system only runs trusted applications.
- **Use of EDR (Endpoint Detection and Response)** – EDR solutions can detect anomalous API calls or thread activity associated with APC injections. Behavioral analysis tools can also help identify malicious patterns in thread execution.


