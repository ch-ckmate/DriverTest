# Ofsec Driver

#### Setup
Vmware win10:
bcdedit /debug on
bcdedit /set testsigning on
bcdedit /dbgsettings serial debugport:2 baudrate:115200 (check serial port)

![image](https://user-images.githubusercontent.com/5458695/233830268-5ab5992e-4caa-489e-a445-30f1e51d25ce.png)

Create “HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter”, Add value “DEFAULT” : REG_DWORD : 0xFFFFFFFF and then reboot.

Host: Windbg-> attach  to kernel-> COM -> \\.\pipe\windbg

sc create dbgtest type=kernel binPath="\\vmware-host\Shared Folders\Windbg-Dev\Test\x64\Debug\Test.sys"

[Offset Library](https://www.vergiliusproject.com/)
