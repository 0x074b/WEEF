# Process Ghosting
***Process Ghosting** is an advanced **evasion technique** that allows attackers to execute malicious code **without ever being written as a valid file on disk**.
It was first documented by security researchers as a way to bypass modern security solutions like **antivirus (AV) and Endpoint Detection & Response (EDR)**.*

*This method abuses how Windows handles file execution, allowing a process to be **created from a deleted or unlinked file**, making it difficult for security tools to detect and analyze.*

## Why Use Process Ghosting?

- **Bypasses Antivirus and EDR solutions** – The file is removed before execution, preventing detection.
- **Avoids file-based scanning** – Since the file does not exist on disk at execution time, traditional AV solutions cannot scan it.
- **Achieves stealthy execution** – The malware runs as a normal process without a visible file.
- **Does not require NTFS transactions** – Unlike **Process Doppelgänging**, this technique does not rely on NTFS transactional mechanisms.

> [!NOTE]
> **Process Ghosting** is more **stealthy** than traditional injection methods because it **does not require file persistence on disk**.

# How Process Ghosting Works
*Process Ghosting consists of three main steps:*

### 1. Create a Malicious File in a Suspended State
  - The attacker **creates a new file** containing the **malicious executable**.
  - The file is **not yet executed**, and the attacker keeps control over it.

### 2. Delete or Unlink the File Before Execution
  - The attacker **deletes or renames the file** before it is executed.
  - Even though the file **is removed from the filesystem**, a handle to it remains valid in memory.
  - Antivirus and EDR tools **can no longer scan the file**, as it no longer exists in the traditional file system.

### 3. Execute the Process from the Deleted File
  - The attacker uses ```NtCreateProcessEx``` or similar API calls to **execute the process from the deleted file**.
  - Windows allows the execution of a process even if the file is already deleted, **creating a ghost process**.

# Process Ghosting Attack Diagram
*Here’s a step-by-step visual representation of how Process Ghosting works:*
```
┌──────────────────────────┐
│ 1. Create Malicious File │  
│ File is written to disk  │  
│ but not executed yet     │  
└───────────┬──────────────┘  
            │  
            ▼  
┌──────────────────────────┐  
│ 2. Delete or Unlink File │  
│ File is removed from FS  │  
│ but handle still exists  │  
└───────────┬──────────────┘  
            │  
            ▼  
┌──────────────────────────┐  
│ 3. Execute from Memory   │  
│ Process starts from RAM  │  
│ despite file deletion    │  
└──────────────────────────┘  
```

# Detection and Defense Against Process Ghosting
## How to Detect Process Ghosting?

- **Monitor File Deletion Before Execution** – Watch for processes started from recently deleted files.
- **Detect Unlinked File Handles** – Security tools can track processes holding handles to deleted files.
- **Behavioral Analysis** – If a process starts but has no valid file path, it may be using Ghosting.
- **Track API Calls** – Look for ```NtCreateProcessEx```, ```NtSetInformationFile``` being used in suspicious ways.

## Defense Techniques

- **Use Advanced EDR Solutions** – Traditional AV may fail; behavioral monitoring is required.
- **Monitor Process Execution Paths** – Ensure that executed files actually exist in the filesystem.
- **Restrict File Handle Manipulation** – Prevent non-administrative users from unlinking or deleting active executable files.
- **Enable Security Logging** – Windows Event Logging can capture unusual process behaviors.



