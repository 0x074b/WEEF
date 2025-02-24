# Definition
*The binary fltMC.exe is used to manage minifilter drivers.*
*You can easily load and unload minifilters using this binary.*
*To unload the Sysmon driver you can use*:
```
fltMC unload SysmonDrv
```

![image](https://github.com/0x074b/Defense-Evasion/assets/83349783/9e1d78c6-d47e-45b5-8dab-a96a18e9917e)

*Note that when unloading a minifilter driver by the FilterManager, it will be logged under the System log.*

![image](https://github.com/0x074b/Defense-Evasion/assets/83349783/85b2caa1-afb0-47da-a030-02d0c73e2984)

*If this binary is flagged, we can unload the minifilter driver by calling the ‘FilterUnload’ which is the Win32 equivalent of ‘FltUnloadFilter’. 
It will call the minifilter’s ‘FilterUnloadCallback’ (PFLT_FILTER_UNLOAD_CALLBACK) routine. This is as same as using fltMC which is a Non-mandatory unload.
For calling this API SeLoadDriverPrivilege is required. To obtain this privelege adminsitrative permissions are required.*
