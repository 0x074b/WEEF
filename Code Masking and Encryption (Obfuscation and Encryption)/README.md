# Introduction
### Code Masking and Encryption (Obfuscation and Encryption)
*(Techniques aimed at hiding, transforming or encrypting malicious code to avoid static and heuristic detection.)*

*The main goal of these techniques is to make malicious code unrecognizable to antivirus, Endpoint Detection and Response (EDR), and forensic analysis tools. These methods mainly target static analysis (signature-based) and heuristic analysis by transforming the structure of the malware.*

# Encryption and Encoding Techniques
*Methods to hide sensitive payloads and strings by dynamically transforming them.*
<ul>
  <li>Payload Encryption</li>
  <ul>
    <li>Using algorithms like AES, RC4, XOR to encrypt the payload.</li>
    <li>The malware decrypts its code in memory only at runtime.</li>
    <li>Example: A dropper retrieves an AES-encrypted payload and decrypts it at runtime.</li>
    <br/>
  </ul>
  <li>Sensitive String Encoding (String Obfuscation)</li>
  <ul>
    <li>Encoding strings to avoid detection by YARA rules or AV signatures.</li>
    <li>Common methods: Base64, ROT13, XOR, URL encoding.</li>
    <li>Example: <code>QmFzZTY0IGlzIHVzZWQgdG8gaGlkZSB0ZXh0</code> (Base64).</li>
    <br/>
  </ul>
  <li>Compression and Encryption of Executables</li>
  <ul>
    <li>Using <code>UPX</code>, <code>MPRESS</code>, <code>Themida</code>, <code>VMProtect</code> to hide the binary.</li>
    <li>Some packers include protection against dynamic analysis.</li>
    <li>Example: <code>UPX --best --lzma file.exe</code> to compress an executable.</li>
    <br/>
  </ul>
  <li>Self-Modifying Code</li>
  <ul>
    <li>The code self-modifies after loading into memory, making static analysis impossible.</li>
    <li>Can be used in combination with polymorphism.</li>
    <br/>
  </ul>
  <li>Steganography</li>
  <ul>
    <li>Hide malicious code in harmless files (images, audios, documents).</li>
    <li>Example: Load hidden shellcode into a .png file.</li>
    <br/>
  </ul>
  <li>Polyglots and Polyglot Files</li>
  <ul>
    <li>Creation of valid files in several formats <code>.jpg.exe</code>, <code>.pdf.zip</code>).</li>
    <li>Exploiting applications that interpret them differently.</li>
    <br/>
  </ul>
</ul>

# Obfuscation of Windows Code and APIs
*Techniques to prevent analysis and reverse engineering by making the structure of the code more complex.*
<ul>
  <li>Obfuscation of Windows APIs</li>
  <ul>
    <li>Replacement of direct calls (<code>CreateProcessA</code>, <code>VirtualAllocEx</code>) by dynamic resolutions.</li>
    <li>Execution via <code>LoadLibrary</code> and <code>GetProcAddress</code>.</li>
    <li>Example:
        <code>HMODULE hLib = LoadLibraryA("kernel32.dll");</code>
        <code>FARPROC pFunc = GetProcAddress(hLib, "VirtualAlloc");</code>
    </li>
    <br/>
  </ul>
  <li>Obcent control of the Control Flow (Control Flow Obfuscation)</li>
  <ul>
    <li>Added false conditional blocks and unnecessary jumps to disrupt the analysis.</li>
    <li>Example: Unnecessary loops, redundant instructions.</li>
    <br/>
  </ul>
  <li>Transfers and conversions of the Code</li>
  <ul>
    <li>Addition of "noise" code that does not change the logic but complicates reading.</li>
    <li>Replacement of certain instructions by longer equivalents.</li>
    <br/>
  </ul>
  <li>Polymorphism and Metamorphism</li>
  <ul>
    <li>Polymorphism: The code changes slightly with each execution.</li>
    <li>Metamorphism: The code is completely rewritten without changing its functionality.</li>
    <br/>
  </ul>
  <li>Deactivation of Windows Protectors</li>
  <ul>
    <li>Deactivation of AMSI (Antimalware Scan Interface) in memory to run PowerShell scripts without detection.</li>
    <li>Example of AMSI bypass in PowerShell:
    <code>
      [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic, Static').SetValue($null, $true)
    </code></li>
    <br/>
  </ul>
</ul>




