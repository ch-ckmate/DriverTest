# DriverTest

Vmware win10:
bcdedit /debug on
bcdedit /dbgsettings serial debugport:2 baudrate:115200 (check serial port)
![image](https://user-images.githubusercontent.com/5458695/233830268-5ab5992e-4caa-489e-a445-30f1e51d25ce.png)

Host: Windbg-> attach  to kernel-> COM -> \\.\pipe\windbg
