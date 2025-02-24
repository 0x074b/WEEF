# Table of contents


# Introduction
## Code Masking and Encryption (Obfuscation and Encryption)
*(Techniques aimed at hiding, transforming or encrypting malicious code to avoid static and heuristic detection.)

The main goal of these techniques is to make malicious code unrecognizable to antivirus, Endpoint Detection and Response (EDR), and forensic analysis tools. These methods mainly target static analysis (signature-based) and heuristic analysis by transforming the structure of the malware.*

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
    <li>Example: ```QmFzZTY0IGlzIHVzZWQgdG8gaGlkZSB0ZXh0``` (Base64).</li>
  </ul>
  <li>Compression and Encryption of Executables</li>
  <ul>
    <li>Using ```UPX```, ```MPRESS```, ```Themida```, ```VMProtect``` to hide the binary.</li>
    <li>Some packers include protection against dynamic analysis.</li>
    <li>Example: ```UPX --best --lzma file.exe``` to compress an executable.</li>
  </ul>
  <li>Self-Modifying Code</li>
  <ul>
    <li>The code self-modifies after loading into memory, making static analysis impossible.</li>
    <li>Can be used in combination with polymorphism.</li>
  </ul>
  <li>Steganography</li>
  <ul>
    <li>Hide malicious code in harmless files (images, audios, documents).</li>
    <li>Example: Load hidden shellcode into a .png file.</li>
  </ul>
  <li>Polyglots and Polyglot Files</li>
  <ul>
    <li>Creation of valid files in several formats (```.jpg.exe```, ```.pdf.zip```).</li>
    <li>Exploiting applications that interpret them differently.</li>
  </ul>
</ul>

















