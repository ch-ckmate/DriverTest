#include <ntddk.h>
#include "ioctl.h"

void DriverClean(PDRIVER_OBJECT DriverObject);
UNICODE_STRING  deviceName = RTL_CONSTANT_STRING(L"\\Device\\ofsecdrv");
UNICODE_STRING  syymlink = RTL_CONSTANT_STRING(L"\\??\\ofsecdrv");
PVOID allocone;
NTSTATUS CreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);


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
