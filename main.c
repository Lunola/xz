#define GNU_EFI_USE_MS_ABI 1
#define MicrosoftCallingType __attribute__((ms_abi))

#include <efi.h>
#include <efilib.h>
#include "dummy.h"

#define baseOperation 0x2561
#define VARIABLE_NAME L"Neirox0z"

#define COMMAND_MAGIC baseOperation*0x4351

typedef struct _DummyProtocolData {
    UINTN blank;
} DummyProtocolData;

typedef unsigned long long ptr64;

typedef struct _MemoryCommand 
{
	int magic;
	int operation;
	ptr64 data[10];
} 

typedef int (MicrosoftCallingType *PsLookupProcessByProcessId)(
    void* ProcessId,
    void** OutPEProcess
);

typedef void* (MicrosoftCallingType *PsGetProcessSectionBaseAddress)(
    void* PEProcess
);

typedef int (MicrosoftCallingType *MmCopyVirtualMemory)(
    void* SourceProcess,
    void* SourceAddress,
    void* TargetProcess,
    void* TargetAddress,
    UINT64 BufferSize,
    char PreviousMode,
    void* ReturnSize
);

static const EFI_GUID ProtocolGuid = { 0x2f84893e, 0xfd5e, 0x2038, {0x8d, 0x9e, 0x20, 0xa7, 0xaf, 0x9c, 0x32, 0xf1} };
static const EFI_GUID VirtualGuid = { 0x13FA7698, 0xC831, 0x49C7, { 0x87, 0xEA, 0x8F, 0x43, 0xFC, 0xC2, 0x51, 0x96 } };
static const EFI_GUID ExitGuid = { 0x27ABF055, 0xB1B8, 0x4C26, { 0x80, 0x48, 0x74, 0x8F, 0x37, 0xBA, 0xA2, 0xDF } };

static EFI_SET_VARIABLE oSetVariable = NULL;

static EFI_EVENT NotifyEvent = NULL;
static EFI_EVENT ExitEvent = NULL;
static BOOLEAN Virtual = FALSE;
static BOOLEAN Runtime = FALSE;

static PsLookupProcessByProcessId GetProcessByPid = NULL;
static PsGetProcessSectionBaseAddress GetBaseAddress = NULL;
static MmCopyVirtualMemory MCopyVirtualMemory = NULL;

static EFI_STATUS RunCommand(MemoryCommand* cmd) {
    if (cmd->magic != COMMAND_MAGIC) {
        return EFI_ACCESS_DENIED;
    }

    switch (cmd->operation) {
        case (BASE_OPERATION * 0x823):
            return HandleMemoryCopy(cmd);
        case (BASE_OPERATION * 0x612):
            return SetupProcessHooks(cmd);
        case (BASE_OPERATION * 0x289):
            return GetProcessBaseAddress(cmd);
        default:
            return EFI_UNSUPPORTED;
    }
}

static EFI_STATUS HandleMemoryCopy(MemoryCommand* cmd) {
    void* src_process_id = (void*)cmd->data[0];
    void* src_address = (void*)cmd->data[1];
    void* dest_process_id = (void*)cmd->data[2];
    void* dest_address = (void*)cmd->data[3];
    UINT64 size = cmd->data[4];
    void* resultAddr = (void*)cmd->data[5];

    if (src_process_id == (void*)4ULL) {
        // Direct memory copy
        CopyMem(dest_address, src_address, size);
    } else {
        void* SrcProc = NULL;
        void* DstProc = NULL;
        UINT64 size_out = 0;
        int status = 0;
        
        status = GetProcessByPid(src_process_id, &SrcProc);
        if (status < 0) {
            *(UINT64*)resultAddr = status;
            return EFI_SUCCESS;
        }
        
        status = GetProcessByPid(dest_process_id, &DstProc);
        if (status < 0) {
            *(UINT64*)resultAddr = status;
            return EFI_SUCCESS;
        }
        
        *(UINT64*)resultAddr = MCopyVirtualMemory(SrcProc, src_address, DstProc, dest_address, size, 1, &size_out);
    }
    return EFI_SUCCESS;
}

static EFI_STATUS SetupProcessHooks(MemoryCommand* cmd) {
    GetProcessByPid = (PsLookupProcessByProcessId)cmd->data[0];
    GetBaseAddress = (PsGetProcessSectionBaseAddress)cmd->data[1];
    MCopyVirtualMemory = (MmCopyVirtualMemory)cmd->data[2];
    UINT64 resultAddr = cmd->data[3];
    *(UINT64*)resultAddr = 1;
    return EFI_SUCCESS;
}

static EFI_STATUS GetProcessBaseAddress(MemoryCommand* cmd) {
    void* pid = (void*)cmd->data[0];
    void* resultAddr = (void*)cmd->data[1];
    void* ProcessPtr = NULL;

    if (GetProcessByPid(pid, &ProcessPtr) < 0 || ProcessPtr == NULL) {
        *(UINT64*)resultAddr = 0; // Process not found
        return EFI_SUCCESS;
    }
    
    *(UINT64*)resultAddr = (UINT64)GetBaseAddress(ProcessPtr); // Return Base Address
    return EFI_SUCCESS;
}

EFI_STATUS EFIAPI HookedSetVariable(
    CHAR16 *VariableName,
    EFI_GUID *VendorGuid,
    UINT32 Attributes,
    UINTN DataSize,
    VOID *Data
) {
    if (Virtual && Runtime) {       
        if (VariableName != NULL && VariableName[0] != CHAR_NULL && VendorGuid != NULL) {                     
            if (StrnCmp(VariableName, VARIABLE_NAME, (sizeof(VARIABLE_NAME) / sizeof(CHAR16)) - 1) == 0) {              
                if (DataSize == 0 && Data == NULL) {
                    return EFI_SUCCESS; // Skip no data
                }

                if (DataSize == sizeof(MemoryCommand)) {
                    return RunCommand((MemoryCommand*)Data); // Process command
                }
            }
        }
    }

    return oSetVariable(VariableName, VendorGuid, Attributes, DataSize, Data); // Call original SetVariable
}

static VOID EFIAPI SetVirtualAddressMapEvent(EFI_EVENT Event, VOID* Context) {
    RT->ConvertPointer(0, (VOID**)&oSetVariable);
    RT->ConvertPointer(0, (VOID**)&oGetTime);
    RT->ConvertPointer(0, (VOID**)&oSetTime);
    RT->ConvertPointer(0, (VOID**)&oGetWakeupTime);
    RT->ConvertPointer(0, (VOID**)&oSetWakeupTime);
    RT->ConvertPointer(0, (VOID**)&oSetVirtualAddressMap);
    RT->ConvertPointer(0, (VOID**)&oConvertPointer);
    RT->ConvertPointer(0, (VOID**)&oGetVariable);
    RT->ConvertPointer(0, (VOID**)&oGetNextVariableName);
    RT->ConvertPointer(0, (VOID**)&oGetNextHighMonotonicCount);
    RT->ConvertPointer(0, (VOID**)&oResetSystem);
    RT->ConvertPointer(0, (VOID**)&oUpdateCapsule);
    RT->ConvertPointer(0, (VOID**)&oQueryCapsuleCapabilities);
    RT->ConvertPointer(0, (VOID**)&oQueryVariableInfo);
    
    // Enable virtual mappings
    RtLibEnableVirtualMappings();

    NotifyEvent = NULL; // Null and close the event to prevent re-calls
    Virtual = TRUE; // We are now in virtual address space
}

static VOID EFIAPI ExitBootServicesEvent(EFI_EVENT Event, VOID* Context) {
    BS->CloseEvent(ExitEvent);
    ExitEvent = NULL;

    BS = NULL; // Boot services are now not available
    Runtime = TRUE; // We are booting the OS now

    // Display confirmation text
    ST->ConOut->SetAttribute(ST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLUE);
    ST->ConOut->ClearScreen(ST->ConOut);
    Print(L"Driver seems to be working as expected! Windows is booting now...\n");
}

static VOID* SetServicePointer(EFI_TABLE_HEADER *ServiceTableHeader, VOID **ServiceTableFunction, VOID *NewFunction) {
    if (ServiceTableFunction == NULL || NewFunction == NULL) return NULL;

    ASSERT(BS != NULL); // Check for boot services pointer validity
    ASSERT(BS->CalculateCrc32 != NULL);

    CONST EFI_TPL Tpl = BS->RaiseTPL(TPL_HIGH_LEVEL);
    VOID* OriginalFunction = *ServiceTableFunction;
    *ServiceTableFunction = NewFunction;

    // Update CRC32 signature
    ServiceTableHeader->CRC32 = 0;
    BS->CalculateCrc32((UINT8*)ServiceTableHeader, ServiceTableHeader->HeaderSize, &ServiceTableHeader->CRC32);
    BS->RestoreTPL(Tpl);

    return OriginalFunction;
}

static EFI_STATUS EFI_FUNCTION efi_unload(IN EFI_HANDLE ImageHandle) {
    return EFI_ACCESS_DENIED; // Prevent unloading until complete reboot
}


// EFI driver unload routine
static
EFI_STATUS
EFI_FUNCTION
efi_unload(IN EFI_HANDLE ImageHandle)
{
	// We don't want our driver to be unloaded 
	// until complete reboot
	return EFI_ACCESS_DENIED;
}

EFI_STATUS efi_main(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
    InitializeLib(ImageHandle, SystemTable);

    EFI_LOADED_IMAGE *LoadedImage = NULL;
    EFI_STATUS status = BS->OpenProtocol(ImageHandle, &LoadedImageProtocol,
                                         (void**)&LoadedImage, ImageHandle,
                                         NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  
    if (EFI_ERROR(status)) {
        Print(L"Can't open protocol: %d\n", status);
        return status;
    }

    DummyProtocolData dummy = { 0 };
    status = LibInstallProtocolInterfaces(&ImageHandle, &ProtocolGuid, &dummy, NULL);
      
    if (EFI_ERROR(status)) {
        Print(L"Can't register interface: %d\n", status);
        return status;
    }

    LoadedImage->Unload = (EFI_IMAGE_UNLOAD)efi_unload;

    status = BS->CreateEventEx(EVT_NOTIFY_SIGNAL,
                                TPL_NOTIFY,
                                SetVirtualAddressMapEvent,
                                NULL,
                                &VirtualGuid,
                                &NotifyEvent);

    if (EFI_ERROR(status)) {
        Print(L"Can't create event (SetVirtualAddressMapEvent): %d\n", status);
        return status;
    }

    status = BS->CreateEventEx(EVT_NOTIFY_SIGNAL,
                                TPL_NOTIFY,
                                ExitBootServicesEvent,
                                NULL,
                                &ExitGuid,
                                &ExitEvent);

    if (EFI_ERROR(status)) {
        Print(L"Can't create event (ExitBootServicesEvent): %d\n", status);
        return status;
    }

    // Hook SetVariable and other runtime service functions
    oSetVariable = (EFI_SET_VARIABLE)SetServicePointer(&RT->Hdr, (VOID**)&RT->SetVariable, (VOID**)&HookedSetVariable);
    // Hook other service functions appropriately...

    // Print confirmation text
    Print(L"\nDriver has been loaded successfully. You can now boot to the OS.\n");
    Print(L"If you don't see a blue screen while booting, disable Secure Boot!.\n");
    
    return EFI_SUCCESS;
}
