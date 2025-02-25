# Process Doppelgänging
***Process Doppelgänging** is a fairly advanced **code injection** and **evasion technique** that exploits the way Windows handles **NTFS transactions**. 
Unlike **Process Hollowing**, which modifies the memory of a suspended process, **Process Doppelgänging creates a completely new process using a fake, malicious image while bypassing traditional detection methods**.*

*This technique is often used by **malware, APT groups, and red teamers** to evade antivirus (AV) and Endpoint Detection & Response (EDR) solutions.*

## Why Use Process Doppelgänging?
- **Bypasses antivirus and EDR** – Since no actual file is written to disk, traditional file-scanning mechanisms fail.
- **Hides malicious execution** – The process appears legitimate in memory.
- **Leaves no trace on disk** – Uses the NTFS transaction mechanism to load malicious code without writing it permanently.
- **Avoids process creation detection** – The execution does not follow standard process creation workflows, making it stealthier.

> [!NOTE]
> **Process Doppelgänging** is more **stealthy** than Process Hollowing because it **does not require** an actual **file on disk**.

# How Process Doppelgänging Works
*Process Doppelgänging consists of four main steps:*

### 1. Transactional File Creation (TXF Abuse)
  - The attacker **creates a malicious file** inside an **NTFS transaction** (using Windows Transactional NTFS – TxF).
  - The file exists **only within the transaction**, so it is **invisible** to security tools and never actually saved to disk.

### 2. Transaction Rollback
  - Instead of committing the transaction, the attacker **rolls it back**.
  - The file **vanishes** from the file system, but Windows still allows access to its **handle** in memory.

### 3. Process Execution via Section Mapping
  - The attacker **creates a process** and maps the malicious executable from the rolled-back transaction into memory.
  - Since the file does not exist on disk, **security software cannot scan it**.

### 4. Process Execution
  - The process is started as if it were a legitimate executable, but it is actually running **malicious code**.
  - The malware is now running **without ever being written to disk** and appears as a normal process.

# Process Doppelgänging Attack Diagram
*Here’s a step-by-step visual representation of how Process Doppelgänging works:*
```
┌──────────────────────────┐
│ 1. Create Transaction    │  
│ (NTFS TxF File)          │  
│ Malicious EXE is created │  
│ but NOT committed        │  
└───────────┬──────────────┘  
            │  
            ▼  
┌──────────────────────────┐  
│ 2. Rollback Transaction  │  
│ File is removed from FS  │  
│ but still exists in RAM  │  
└───────────┬──────────────┘  
            │  
            ▼  
┌──────────────────────────┐  
│ 3. Map Section & Execute │  
│ Process runs from memory │  
│ without touching disk    │  
└───────────┬──────────────┘  
            │  
            ▼  
┌──────────────────────────┐  
│ 4. Run Malicious Code    │  
│ Process looks legitimate │  
│ but executes malware     │  
└──────────────────────────┘  
```

# Detection and Defense Against Process Doppelgänging
## How to Detect Process Doppelgänging?

- **Monitor NTFS Transactions** – Security tools should watch for unusual file transactions and rollbacks.
- **Track Memory Execution** – Processes loading sections from deleted files or rollback transactions are suspicious.
- **Behavioral Analysis** – If a process starts from a non-existent file, it may be Doppelgänging.
- **Detect API Calls** – Watch for calls like ```CreateTransaction```, ```RollbackTransaction```, ```NtCreateSection```.

## Defense Techniques

- **Use Endpoint Detection & Response (EDR)** – Solutions that track process behavior can detect anomalies.
- **Restrict NTFS Transaction Usage** – If not needed, disable TxF features.
- **Monitor Memory Execution** – Detect processes running from unmapped memory sections.
- **Enable Advanced Logging** – Windows Event Logging can capture unusual process behaviors.


