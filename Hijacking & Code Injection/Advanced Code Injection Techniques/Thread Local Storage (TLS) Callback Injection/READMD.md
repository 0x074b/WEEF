# Thread Local Storage (TLS) Callback Injection
***Thread Local Storage (TLS) Callback Injection** is a stealthy **code injection** technique that exploits **TLS callbacks** to execute malicious code **before the main entry point of an application**.
This method allows attackers to run code before standard execution flow begins, bypassing security monitoring tools that hook into ```main()``` or ```WinMain()```.*

*This technique is particularly effective for **evasion**, as many security tools do not inspect TLS callbacks when scanning executable files.*

## Why Use TLS Callback Injection?

- **Stealthy Execution** – The code runs before the program’s main function, making detection difficult.
- **Avoids API Hooking Detection** – Security solutions that monitor ```CreateRemoteThread()``` or ```WriteProcessMemory()``` do not track TLS callbacks.
- **Ideal for Malware Evasion** – Many sandbox environments do not execute TLS callbacks, allowing malware to remain undetected.
- **Persistence & Exploitation** – Can be used to inject malicious code early in a process’s lifecycle, before security defenses activate.

# How TLS Callback Injection Works?
*TLS is a mechanism that **stores thread-specific data** in Windows executables. It supports **TLS Callbacks**, which execute automatically when:*

- A thread starts or exits.
- A process starts or terminates.

**Attackers modify the TLS callback table in a PE (Portable Executable) file to execute malicious code before the program starts.*

### 1. Modifying a PE File to Include a TLS Callback

- The attacker **modifies an executable’s PE header** to insert a new TLS callback pointing to their **malicious code**.
- TLS callbacks are located in the ```.tls``` section of the PE file.

```
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma section(".CRT$XLB", long, read)
 
void NTAPI MyTLSCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    MessageBoxA(NULL, "Injected via TLS Callback!", "Malware", MB_OK);
}

__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK pTLS_Callbacks[] = { MyTLSCallback, 0 };
```

### 2. When the Process Starts, the Callback Executes

- Windows **automatically executes** any TLS callbacks before ```main()```, ```WinMain()```, or ```DllMain()```.
- The injected callback runs **before security tools attach hooks to the process**.

### 3. Injecting a Malicious TLS Callback in an Existing Executable

- Attackers can **modify the PE header** of an existing application to insert their own TLS callback.
- The ```IMAGE_DIRECTORY_ENTRY_TLS``` entry in the PE structure is edited to include a pointer to **malicious shellcode**.

```
IMAGE_TLS_DIRECTORY tlsDirectory = { 0 };
PIMAGE_TLS_CALLBACK tlsCallbacks[] = { MyMaliciousCode, NULL };

// Overwrite TLS directory entry in the PE header
WriteProcessMemory(hProcess, (LPVOID)&peHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS], &tlsDirectory, sizeof(tlsDirectory), NULL);
```

# Diagram of TLS Callback Injection
```
        ┌──────────────────────────┐
        │ Attacker                 │
        │ (Modifies PE File)       │
        └───────┬──────────────────┘
                │
                ▼
        ┌──────────────────────────┐
        │ Target Process           │
        │ - Modified .tls Section  │◄─── [1] Injected TLS Callback
        │ - Executes Before Main() │◄─── [2] Early Execution
        │ - Runs Malicious Code    │◄─── [3] Malware Executes
        └──────────────────────────┘
```

# Defense Against TLS Callback Injection
*Although the TLS callback injections are stealthy, defensive measures exist:*

## Behavioral Detection

- **Analyze PE headers for unusual TLS callbacks** – Most applications do not have TLS callbacks; unexpected entries should be inspected.
- **Monitor early-stage execution behavior** – Detecting execution before ```main()``` may indicate TLS abuse.
- **Detect memory modifications in the .tls section** – Unexpected writes to this section may suggest injection.

## Mitigation Strategies

- **Use Static Analysis Tools** – Tools like **PE-Bear**, **CFF Explorer**, and **Pestudio** can detect TLS callbacks in PE files.
- **Implement Memory Integrity Checks** – Restrict modifications to executable sections, preventing rogue TLS entries.
- **Monitor API Calls in the PE Loader** – Hook ```LdrpCallTlsInitializers()``` to detect suspicious callbacks.


