#pragma once
#define ImageFileName 0x5A8 // EPROCESS::ImageFileName
#define ActiveThreads 0x5F0 // EPROCESS::ActiveThreads
#define ThreadListHead 0x5E0 // EPROCESS::ThreadListHead
#define ActiveProcessLinks 0x448 // EPROCESS::ActiveProcessLinks
#define FIRST_DRIVER_DEVICE 0x8000
#define  FIRST_DRIVER_IOCTL_ONE CTL_CODE(FIRST_DRIVER_DEVICE,0x8000,METHOD_NEITHER,FILE_ANY_ACCESS)