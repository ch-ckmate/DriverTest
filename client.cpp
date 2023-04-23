#include <Windows.h>
#include <stdio.h>
#include "ioctl.h"

int main(){
    HANDLE hDriver=CreateFile("\\\\.\\ofsecdrv",GENERIC_WRITE,FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if (hDriver==INVALID_HANDLE_VALUE){
        printf("[!] %s (%d)", "Failed to open handle",  GetLastError());
        return 1;
    }
    BOOL success=DeviceIoControl(hDriver,FIRST_DRIVER_IOCTL_ONE,NULL,0,NULL,0,NULL,NULL);
    if(success){
        printf("Done\n");
    }else{
        printf("Failed\n");
    }
    CloseHandle((hDriver));
}
