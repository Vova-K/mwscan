
#include <initguid.h>
#include "main.h"
#include <ntdddisk.h>
#include <dontuse.h>
#include <suppress.h>
#include "utils.h"
#include "context.h"
#include "scanner.h"

MW_GLOBAL_DATA Globals;

DRIVER_INITIALIZE DriverEntry;

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

NTSTATUS DriverUnload(_Unreferenced_parameter_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS DoInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
NTSTATUS DoInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);
VOID DoInstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS FltObjects, _Unreferenced_parameter_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);
VOID DoInstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS FilterPreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS FilterPostCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);
NTSTATUS TrNotificationCallback(_Unreferenced_parameter_ PCFLT_RELATED_OBJECTS FltObjects, _In_ PFLT_CONTEXT TransactionContext, _In_ ULONG TransactionNotification);
NTSTATUS ScanAbortCallback(_Unreferenced_parameter_ PFLT_INSTANCE Instance, _In_ PFLT_CONTEXT Context, _Unreferenced_parameter_ PFLT_CALLBACK_DATA Data);

//
//  Local routines
//
NTSTATUS GetTransactionResult(_In_ PKTRANSACTION Transaction, _Out_ PULONG TxOutcome);
NTSTATUS ProcessTransactions(_In_ PCFLT_RELATED_OBJECTS FltObjects, _Inout_ PMW_STREAM_CONTEXT StreamContext);
NTSTATUS ProcessTransactionResult(_Inout_ PMW_TRANSACTION TransactionContext, _In_ ULONG TransactionOutcome);

NTSTATUS PrepareScan(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ UCHAR IOMajorFunctionAtScan, _In_ BOOLEAN inTransaction, _Inout_ PMW_STREAM_CONTEXT StreamContext);

BOOLEAN IsVolumeOnCsvDisk(_In_ PFLT_VOLUME Volume);
BOOLEAN IsStreamAlternate(_Inout_ PFLT_CALLBACK_DATA Data);
NTSTATUS IsFileEncrypted(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject, _Out_ PBOOLEAN Encrypted);

NTSTATUS CheckForCsvfs(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects);
BOOLEAN CheckForCsvDlEcp(_In_ PFLT_FILTER Filter, _In_ PFLT_CALLBACK_DATA Data);
BOOLEAN CheckForPrefetchEcp(_In_ PFLT_FILTER Filter, _In_ PFLT_CALLBACK_DATA Data);

NTSTATUS GetTransactionContext(_In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_ PMW_TRANSACTION *TransactionContext);

NTSTATUS CreateFileStreamContext(_In_ PFLT_FILTER Filter, _Outptr_ PMW_STREAM_CONTEXT *StreamContext);
NTSTATUS CreateStreamHandleContext(_In_ PFLT_FILTER Filter, _Outptr_ PMW_STREAMHANDLE *StreamHandleContext);

VOID StreamContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType);
VOID TransactionContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType);
VOID SectionContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType);
VOID InstanceContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)

#pragma alloc_text(PAGE, DoInstanceSetup)
#pragma alloc_text(PAGE, DoInstanceQueryTeardown)

#pragma alloc_text(PAGE, DoInstanceTeardownStart)
#pragma alloc_text(PAGE, DoInstanceTeardownComplete)

#pragma alloc_text(PAGE, FilterPreCreate)
#pragma alloc_text(PAGE, FilterPostCreate)

#pragma alloc_text(PAGE, TrNotificationCallback)
#pragma alloc_text(PAGE, ScanAbortCallback)

#pragma alloc_text(PAGE, GetTransactionResult)
#pragma alloc_text(PAGE, ProcessTransactions)
#pragma alloc_text(PAGE, ProcessTransactionResult)

#pragma alloc_text(PAGE, PrepareScan)

#pragma alloc_text(PAGE, IsVolumeOnCsvDisk)
#pragma alloc_text(PAGE, IsStreamAlternate)
// IsFileEncrypted - non paged

#pragma alloc_text(PAGE, CheckForCsvfs)
#pragma alloc_text(PAGE, CheckForCsvDlEcp)
#pragma alloc_text(PAGE, CheckForPrefetchEcp)

#pragma alloc_text(PAGE, GetTransactionContext)

#pragma alloc_text(PAGE, CreateFileStreamContext)
#pragma alloc_text(PAGE, CreateStreamHandleContext)

#pragma alloc_text(PAGE, StreamContextCleanup)
#pragma alloc_text(PAGE, TransactionContextCleanup)
#pragma alloc_text(PAGE, SectionContextCleanup)
#pragma alloc_text(PAGE, InstanceContextCleanup)

#endif

FORCEINLINE PERESOURCE DoAllocateResource()
{
    return (PERESOURCE)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(ERESOURCE), MW_RESOURCE_TAG);
}

FORCEINLINE VOID DoFreeResource(_In_ PERESOURCE Resource)
{
    ExFreePoolWithTag(Resource, MW_RESOURCE_TAG);
}

FORCEINLINE PKEVENT DoAllocateKevent()
{
    return (PKEVENT)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(KEVENT), MW_KEVENT_TAG);
}

FORCEINLINE VOID DoFreeKevent(_In_ PKEVENT Event)
{
    ExFreePoolWithTag(Event, MW_KEVENT_TAG);
}

FORCEINLINE VOID _Acquires_lock_(_Global_critical_region_) DoAcquireResourceExclusive(_Inout_ _Acquires_exclusive_lock_(*Resource) PERESOURCE Resource)
{
    FLT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    FLT_ASSERT(ExIsResourceAcquiredExclusiveLite(Resource) ||
               !ExIsResourceAcquiredSharedLite(Resource));

    KeEnterCriticalRegion();
    (VOID) ExAcquireResourceExclusiveLite(Resource, TRUE);
}
/*
FORCEINLINE VOID _Acquires_lock_(_Global_critical_region_) DoAcquireResourceShared( _Inout_ _Acquires_shared_lock_(*Resource) PERESOURCE Resource )
{
	FLT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
	KeEnterCriticalRegion();
	(VOID)ExAcquireResourceSharedLite(Resource, TRUE);
}
*/
FORCEINLINE VOID _Releases_lock_(_Global_critical_region_) _Requires_lock_held_(_Global_critical_region_) DoReleaseResource(_Inout_ _Requires_lock_held_(*Resource) _Releases_lock_(*Resource) PERESOURCE Resource)
{
    FLT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    FLT_ASSERT(ExIsResourceAcquiredExclusiveLite(Resource) ||
               ExIsResourceAcquiredSharedLite(Resource));

    ExReleaseResourceLite(Resource);
    KeLeaveCriticalRegion();
}

/*++
Cancel the file open. This is to be called at post create if the I/O is cancelled.

Arguments:
	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance, its associated volume and file object.

	Status - The status code to be returned for this IRP.

--*/
FORCEINLINE VOID DoCancelFileOpen(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ NTSTATUS Status)
{
    FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
    Data->IoStatus.Status = Status;
    Data->IoStatus.Information = 0;
}
//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    {IRP_MJ_CREATE,
     0,
     FilterPreCreate,
     FilterPostCreate},
    {IRP_MJ_OPERATION_END}};

//
//  Context registraction construct defined in context.c
//

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

    {FLT_STREAM_CONTEXT,
     0,
     StreamContextCleanup,
     sizeof(MW_STREAM_CONTEXT),
     STREAM_CONTEXT_TAG},

    {FLT_STREAMHANDLE_CONTEXT,
     0,
     NULL,
     sizeof(MW_STREAMHANDLE),
     STREAMHANDLE_CONTEXT_TAG},

    {FLT_TRANSACTION_CONTEXT,
     0,
     TransactionContextCleanup,
     sizeof(MW_TRANSACTION),
     TRANSACTION_CONTEXT_TAG},

    {FLT_SECTION_CONTEXT,
     0,
     SectionContextCleanup,
     sizeof(MW_FILE_SECTION_CONTEXT),
     SECTION_CONTEXT_TAG},

    {FLT_INSTANCE_CONTEXT,
     0,
     InstanceContextCleanup,
     sizeof(MW_INSTANCE_CONTEXT),
     INSTANCE_CONTEXT_TAG},

    {FLT_CONTEXT_END}};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION), //  Size
    FLT_REGISTRATION_VERSION, //  Version
    0,                        //  Flags

    ContextRegistration, //  Context
    Callbacks,           //  Operation callbacks

    DriverUnload, //  MiniFilterUnload

    DoInstanceSetup,            //  InstanceSetup
    DoInstanceQueryTeardown,    //  InstanceQueryTeardown
    DoInstanceTeardownStart,    //  InstanceTeardownStart
    DoInstanceTeardownComplete, //  InstanceTeardownComplete

    NULL,                   //  GenerateFileName
    NULL,                   //  NormalizeNameComponentCallback
    NULL,                   //  NormalizeContextCleanupCallback
    TrNotificationCallback, //  TransactionNotificationCallback
    NULL,                   //  NormalizeNameComponentExCallback
    ScanAbortCallback       //  SectionNotificationCallback
};

/*++
Called whenever a new instance is created on a volume. This gives us a chance to decide if we need to attach to this volume or not.

If this routine is not defined in the registration structure, automatic
instances are alwasys created.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Flags describing the reason for this attach request.

Return Value:

STATUS_SUCCESS - attach
STATUS_FLT_DO_NOT_ATTACH - do not attach
--*/

NTSTATUS DoInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    NTSTATUS status;
    PMW_INSTANCE_CONTEXT instanceContext = NULL;
    BOOLEAN isOnCsv = FALSE;

    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    //
    //  Don't attach to network volumes.
    //

    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
    {

        return STATUS_FLT_DO_NOT_ATTACH;
    }

    //
    //  Determine if the filter is attaching to the hidden NTFS volume
    //  that corresponds to a CSV volume. If so do not attach. Note
    //  that it would be feasible for the filter to attach to this
    //  volume as part of a distrubuted filter implementation but that
    //  is beyond the scope of this sample.
    //

    if (VolumeFilesystemType == FLT_FSTYPE_NTFS)
    {
        isOnCsv = IsVolumeOnCsvDisk(FltObjects->Volume);
        if (isOnCsv)
        {
            return STATUS_FLT_DO_NOT_ATTACH;
        }
    }

    status = FltAllocateContext(Globals.Filter, FLT_INSTANCE_CONTEXT, sizeof(MW_INSTANCE_CONTEXT), NonPagedPoolNx, (PFLT_CONTEXT*)&instanceContext);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("failed to allocate instance context: 0x%x", status);
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    //  Setup instance context
    RtlZeroMemory(instanceContext, sizeof(MW_INSTANCE_CONTEXT));
    instanceContext->Volume = FltObjects->Volume;
    instanceContext->Instance = FltObjects->Instance;
    instanceContext->VolumeFSType = VolumeFilesystemType;

    status = FltSetInstanceContext(FltObjects->Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, instanceContext, NULL);

    //  In all cases, we need to release the instance context at this time.
    FltReleaseContext(instanceContext);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("failed to set instance context: 0x%x", status);
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    // Register this instance as a datascan filter. If this call fails the underlying filesystem does not support using the filter manager datascan API.
    // Currently only the the namedpipe and mailslot file systems are unsupported.
    status = FltRegisterForDataScan(FltObjects->Instance);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("FltRegisterForDataScan failed: 0x%x", status);
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

/*++
This is called when an instance is being manually deleted by a
call to FltDetachVolume or FilterDetach thereby giving us a
chance to fail that detach request.

If this routine is not defined in the registration structure, explicit detach requests via FltDetachVolume or FilterDetach will always be failed.

--*/
NTSTATUS DoInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
    return STATUS_SUCCESS;
}
/*++
This is called pre instance deletion
--*/
VOID DoInstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS FltObjects, _Unreferenced_parameter_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    NTSTATUS status;
    PMW_INSTANCE_CONTEXT instanceContext = NULL;

    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
    status = FltGetInstanceContext(FltObjects->Instance, (PFLT_CONTEXT*)&instanceContext);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("FltGetInstanceContext failed: 0x%x", status);
        return;
    }
    FltReleaseContext(instanceContext);
    FltDeleteInstanceContext(FltObjects->Instance, NULL);
}

/*++
This is called post instance deletion
--*/
VOID DoInstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
}

/*++
DriverEntry - driver entry point

Arguments:

DriverObject - Pointer to driver object created by the system to represent this driver.
RegistryPath - Unicode string identifying where the parameters for this driver are located in the registry.

Return Value:
	 status  - status code this operation.
--*/

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_SUCCESS;
    PSECURITY_DESCRIPTOR sd = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);
    RtlZeroMemory(&Globals, sizeof(Globals));

    Globals.DriverIsUnloading = 0;

    DbgPrint("starting %s", DRIVER_NAME);

    do
    {
        status = FltRegisterFilter(DriverObject, &FilterRegistration, &Globals.Filter);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("FltRegisterFilter failed: 0x%x", status);
            break;
        }

        status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("FltBuildDefaultSecurityDescriptor failed: 0x%x", status);
            break;
        }

        status = FltStartFiltering(Globals.Filter);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("FltStartFiltering failed: 0x%x", status);
            break;
        }
	}
	while (0);
    if (sd != NULL)
    {
        FltFreeSecurityDescriptor(sd);
    }

    if (!NT_SUCCESS(status))
    {
        if (NULL != Globals.Filter)
        {
            FltUnregisterFilter(Globals.Filter);
            Globals.Filter = NULL;
        }
    }
    return status;
}

/*++
Unload routine for this miniFilter driver.
Code can fail this unload request if this is not a mandatory unloaded indicated by the Flags parameter.

Arguments:
	Flags - Indicating if this is a mandatory unload.
Return Value:
	The final status of this operation.

--*/
NTSTATUS DriverUnload(_Unreferenced_parameter_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(Flags);
    InterlockedExchange(&Globals.DriverIsUnloading, 1);
    FltUnregisterFilter(Globals.Filter);
    Globals.Filter = NULL;
    return STATUS_SUCCESS;
}

/*++
	Qeury the KTM that how trasnaction was ended.
Arguments:
	Transaction - Pointer to transaction object.
	TxOutcome - Output. Specifies the type of transaction outcome.

Return Value:
	The status of the operation
--*/
NTSTATUS GetTransactionResult(_In_ PKTRANSACTION Transaction, _Out_ PULONG TxOutcome)
{
    HANDLE transactionHandle;
    NTSTATUS status;
    TRANSACTION_BASIC_INFORMATION txBasicInfo = {0};

    PAGED_CODE();
    //get the transaction handle
    status = ObOpenObjectByPointer(Transaction, OBJ_KERNEL_HANDLE, NULL, GENERIC_READ, *TmTransactionObjectType, KernelMode, &transactionHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("ObOpenObjectByPointer failed: 0x%x", status);
        return status;
    }
    //need to close handle afterwards!
    do
    {
        status = ZwQueryInformationTransaction(transactionHandle, TransactionBasicInformation, &txBasicInfo, sizeof(TRANSACTION_BASIC_INFORMATION), NULL);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("ZwQueryInformationTransaction failed: 0x%x", status);
            break;
        }

        *TxOutcome = txBasicInfo.Outcome;
    } while (0);
    ZwClose(transactionHandle);
    return status;
}

/*++
An inline routine that propagates the transaction State to final transaction State in stream context.
--*/
FORCEINLINE VOID SetTransactionFinalState(_Inout_ PMW_STREAM_CONTEXT StreamContext, _In_ ULONG TransactionReslut)
{
    if (TransactionReslut == TransactionOutcomeCommitted)
    {
        MW_INFECTED_STATE oldTxState = (MW_INFECTED_STATE)InterlockedExchange(&StreamContext->TxState, InfectedStateModified);
        switch (oldTxState)
        {
        case InfectedStateModified:
        case InfectedStateInfected:
        case InfectedStateClean:
            InterlockedExchange(&StreamContext->FinalState, oldTxState);
            break;
        default:
            FLT_ASSERTMSG("SetTransactionFinalState does not handle the state", FALSE);
            break;
        }
    }
    SetContextFlagModified(&(StreamContext->TxState));
}

/*++
	Process transaction commitment or rollback

Arguments:

	TransactionContext - Pointer to the minifilter driver's transaction context
	TransactionResult - result of the completed transaction

Return Value:
	STATUS_SUCCESS 
--*/
NTSTATUS ProcessTransactionResult(_Inout_ PMW_TRANSACTION TransactionContext, _In_ ULONG TransactionResult)
{
    PLIST_ENTRY scan;
    PLIST_ENTRY next;
    PMW_STREAM_CONTEXT streamContext = NULL;
    PMW_TRANSACTION oldTxCtx = NULL;

    PAGED_CODE();

    //  Tranversing the stream context list, and sync the TxState -> State.
    DoAcquireResourceExclusive(TransactionContext->Resource);
    LIST_FOR_EACH_SAFE(scan, next, &TransactionContext->ScListHead)
    {

        streamContext = CONTAINING_RECORD(scan, MW_STREAM_CONTEXT, ListInTransaction);
        oldTxCtx = (PMW_TRANSACTION)InterlockedCompareExchangePointer((volatile PVOID*)&streamContext->TransactionContext, NULL, TransactionContext);
        if (oldTxCtx == TransactionContext)
        {
            RemoveEntryList(scan);
            SetTransactionFinalState(streamContext, TransactionResult);
            FltReleaseContext(oldTxCtx);
            FltReleaseContext(streamContext);
        }
        //TODO:report error if not match?
    }
    SetFlag(TransactionContext->Flags, TRANSACTION_FLAGS_LISTDRAINED);
    DoReleaseResource(TransactionContext->Resource);
    return STATUS_SUCCESS;
}

/*++
	Main scan function.

Arguments:
	Data - Pointer to the filter callbackData that is passed to us.
	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure	
	IOMajorFunctionAtScan - Major function of an IRP.
	StreamContext - The stream context of the target file.

Return Value:
	Returns the final status of this operation.
--*/
NTSTATUS PrepareScan(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ UCHAR IOMajorFunctionAtScan, _In_ BOOLEAN inTransaction, _Inout_ PMW_STREAM_CONTEXT StreamContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    LONGLONG fileSize;

    PAGED_CODE();
    status = UtilGetFileSize(FltObjects->Instance, FltObjects->FileObject, &fileSize);

    if (NT_SUCCESS(status) && (0 == fileSize))
    {
        // As if we have 'scanned' this empty file.
        SetContextFlagClean(&(StreamContext->FinalState));
        return STATUS_SUCCESS;
    }

    //
    // It could cause deadlocks if the thread were suspended once we started scanning so enter a critical region.
    FsRtlEnterFileSystem();
    //  Wait here for an existing scan on the stream to complete. Do wait indefinitely since scans themselves will timeout.
    status = FltCancellableWaitForSingleObject(StreamContext->ScanCompleteEvent, NULL, Data);

    if (NT_SUCCESS(status))
    {
        //  Check again in case the file was scanned during the wait and is already known to be clean
        if (IsFileNeedScan(StreamContext))
        {
            {
                status = PerformScan(FltObjects, IOMajorFunctionAtScan, inTransaction, StreamContext);
                if (!NT_SUCCESS(status))
                {
                    DbgPrint("Scan has failed: 0x%x", status);
                }
            }
        }
        //  Signal ScanSynchronizationEvent to release any con-current scan of the stream,
        KeSetEvent(StreamContext->ScanCompleteEvent, 0, FALSE);
    }
    else if (IOMajorFunctionAtScan == IRP_MJ_CREATE)
    {
        // Need to clean up the file object too.
        DoCancelFileOpen(Data, FltObjects, status);
    }
    FsRtlExitFileSystem();
    return status;
}

/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/

/*++

Pre-create completion routine.
Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter

	CompletionContext - If this callback routine returns FLT_PREOP_SUCCESS_WITH_CALLBACK or
            FLT_PREOP_SYNCHRONIZE, this parameter is an optional context pointer to be passed to
            the corresponding post-operation callback routine. Otherwise, it must be NULL.

Return Value:
	FLT_PREOP_SYNCHRONIZE - PostCreate needs to be called back synchronizedly.
	FLT_PREOP_SUCCESS_NO_CALLBACK - PostCreate does not need to be called.
--*/
FLT_PREOP_CALLBACK_STATUS FilterPreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR stackLow;
    ULONG_PTR stackHigh;
    PFILE_OBJECT FileObject = Data->Iopb->TargetFileObject;
    MW_STREAMHANDLE streamHandleContext;

    PAGED_CODE();

    DbgPrint("PreCreate: Entered");
    streamHandleContext.Flags = 0;

    IoGetStackLimits(&stackLow, &stackHigh);
    // Skip stack file objects
    if (((ULONG_PTR)FileObject > stackLow) && ((ULONG_PTR)FileObject < stackHigh))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Donst scan directory open operations
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //  Pre-rename operations which always open a directory.
    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //  Skip paging files.
    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //  Skip DASD
    if (FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Skip scanning any files being opened by CSVFS for its downlevel processing.
    if (CheckForCsvDlEcp(FltObjects->Filter, Data))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    //  Performing IO using a prefetch fileobject could lead to a deadlock.
    if (CheckForPrefetchEcp(FltObjects->Filter, Data))
    {
        SetFlag(streamHandleContext.Flags, MW_PREFETCH);
    }
    //
    *CompletionContext = (PVOID)(UINT_PTR)streamHandleContext.Flags;
    status = CheckForCsvfs(Data, FltObjects);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Ignoring scan on CSVFS: 0x%x", status);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    //  Return FLT_PREOP_SYNCHRONIZE at PreCreate to ensure PostCreate  is in the same thread at passive level.
    //  because EResource can't be acquired at DPC.
    return FLT_PREOP_SYNCHRONIZE;
}

/*++

This is expected to be invoked at post-create.
can enlist the newly allocated transaction context via FltEnlistInTransaction if it needs to.

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure
	StreamContext - The stream context.

Return Value:
	The return value is the status of the operation.
--*/
NTSTATUS ProcessTransactions(_In_ PCFLT_RELATED_OBJECTS FltObjects, _Inout_ PMW_STREAM_CONTEXT StreamContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    PMW_TRANSACTION oldTxCtx = NULL;
    PMW_TRANSACTION transactionContext = NULL;

    PAGED_CODE();

    if (FltObjects->Transaction != NULL)
    {
        status = GetTransactionContext(FltObjects, &transactionContext);

        if (!NT_SUCCESS(status))
        {
            DbgPrint("FindOrCreateTransactionContext Failed: 0x%x", status);
            transactionContext = NULL;
            goto Cleanup;
        }

        //  Enlist it if haven't.
        if (!FlagOn(transactionContext->Flags, TRANSACTION_FLAGS_ENLISTED))
        {
            status = FltEnlistInTransaction(FltObjects->Instance, FltObjects->Transaction, transactionContext, TRANSACTION_NOTIFY_COMMIT_FINALIZE | TRANSACTION_NOTIFY_ROLLBACK);

            if (!NT_SUCCESS(status) && (status != STATUS_FLT_ALREADY_ENLISTED))
            {
                DbgPrint("FltEnlistInTransaction Failed: 0x%x", status);
                goto Cleanup;
            }
            status = STATUS_SUCCESS;
            SetFlag(transactionContext->Flags, TRANSACTION_FLAGS_ENLISTED);
        }
    }

    //  1)
    //    oldTxCtx : NULL
    //    transCtx : B
    //  2)
    //    oldTxCtx : A
    //    transCtx : NULL
    //  3)
    //    oldTxCtx : A
    //    transCtx : B
    //  4)
    //    oldTxCtx : A
    //    transCtx : A
    //  5)
    //    oldTxCtx : NULL
    //    transCtx : NULL
    //

    oldTxCtx = (PMW_TRANSACTION)InterlockedExchangePointer((volatile PVOID*)&StreamContext->TransactionContext, transactionContext);
    // case 1,2,3
    if (oldTxCtx != transactionContext)
    {
        ULONG txOutcome = TransactionOutcomeCommitted;
        // case 1
        if (oldTxCtx == NULL)
        {
            //  This file was not linked in a transaction context yet, and is about to.
            FltReferenceContext(transactionContext);
            DoAcquireResourceExclusive(transactionContext->Resource);

            if (!FlagOn(transactionContext->Flags, TRANSACTION_FLAGS_LISTDRAINED))
            {
                FltReferenceContext(StreamContext); // Q
                InsertTailList(&transactionContext->ScListHead, &StreamContext->ListInTransaction);
            }
            DoReleaseResource(transactionContext->Resource);
            goto Cleanup;
        }

        // case 2,3
        // Query transaction outcome in order to know how we  can process the previously outstanding transaction context.
        status = GetTransactionResult(oldTxCtx->Transaction, &txOutcome);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("QueryTransactionOutcome failed: 0x%x", status);
        }

        DoAcquireResourceExclusive(oldTxCtx->Resource);
        RemoveEntryList(&StreamContext->ListInTransaction);
        DoReleaseResource(oldTxCtx->Resource);

        SetTransactionFinalState(StreamContext, txOutcome);
        // case 3
        if (transactionContext)
        {
            FltReferenceContext(transactionContext);
            DoAcquireResourceExclusive(transactionContext->Resource);
            if (!FlagOn(transactionContext->Flags, TRANSACTION_FLAGS_LISTDRAINED))
            {
                InsertTailList(&transactionContext->ScListHead, &StreamContext->ListInTransaction);
            }
            else
            {
                FltReleaseContext(StreamContext);
            }
            DoReleaseResource(transactionContext->Resource);
        }
        else
        {
            // case 2
            FltReleaseContext(StreamContext); // Release reference count at Q
        }
        // case 2,3
        FltReleaseContext(oldTxCtx); // Release reference count in stream context originally.
    }
    //  case 4, 5 ARE IGNORED!
Cleanup:
    if (transactionContext)
    {
        FltReleaseContext(transactionContext); // Release the ref count grabbed at GetTransactionContext(...)
    }
    return status;
}

/*++

Post-create completion routine. In this routine, stream context and/or transaction context shall be created if not exits.

Note that we only allocate and set the stream context to filter manager at post create.

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.
	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure
	CompletionContext - The completion context set in the pre-create routine.
	Flags - Denotes whether the completion is successful or is being drained.

Return Value:
	The return value is the status of the operation.
--*/
FLT_POSTOP_CALLBACK_STATUS FilterPostCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)

{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN inTransaction = FALSE;

    PMW_STREAM_CONTEXT streamContext = NULL;
    PMW_STREAM_CONTEXT oldStreamContext = NULL;
    PMW_STREAMHANDLE streamHandleContext = NULL;
    ACCESS_MASK desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    {
        NTSTATUS ioStatus = Data->IoStatus.Status;
        if (!NT_SUCCESS(ioStatus) || (ioStatus == STATUS_REPARSE))
        {
            DbgPrint("File creation failed: 0x%x", ioStatus);
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
    }
    {
        BOOLEAN isDir = FALSE;
        status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDir);
        if (NT_SUCCESS(status) && isDir)
        {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
    }
    //  skip the encrypted files
    if (!(FlagOn(desiredAccess, FILE_WRITE_DATA)) && !(FlagOn(desiredAccess, FILE_READ_DATA)))
    {
        BOOLEAN encrypted = FALSE;
        status = IsFileEncrypted(FltObjects->Instance, FltObjects->FileObject, &encrypted);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("GetFileEncrypted failed: 0x%x", status);
        }
        if (encrypted)
        {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
    }
    //  Skip the alternate data stream.
    if (IsStreamAlternate(Data))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //  Skip a prefetch open and flag it so we skip subsequent IO operations on the handle.
    if (FlagOn((ULONG_PTR)CompletionContext, MW_PREFETCH))
    {
        if (!FltSupportsStreamHandleContexts(FltObjects->FileObject))
        {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
        status = CreateStreamHandleContext(FltObjects->Filter, &streamHandleContext);
        if (!NT_SUCCESS(status))
        {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        SetFlag(streamHandleContext->Flags, MW_PREFETCH);

        status = FltSetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, streamHandleContext, NULL);
        FltReleaseContext(streamHandleContext);

        if (!NT_SUCCESS(status))
        {
            // Shouldn't find the handle already set
            ASSERT(status != STATUS_FLT_CONTEXT_ALREADY_DEFINED);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    //  Find or create a stream context
    //

    status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT*)&streamContext);
    if (status == STATUS_NOT_FOUND)
    {
        status = CreateFileStreamContext(FltObjects->Filter, &streamContext);
        if (!NT_SUCCESS(status))
        {
            DbgPrint(" Failed create file stream context: 0x%x", status);
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
        status = UtilGetFileId(FltObjects->Instance, FltObjects->FileObject, &streamContext->FileId);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("Failed to get file id: 0x%x", status);
            SET_INVALID_FILE_ID(streamContext->FileId)
        }

        //
        //  Set the new context we just allocated on the file object
        //

        status = FltSetStreamContext(FltObjects->Instance,
                                     FltObjects->FileObject,
                                     FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                     streamContext,
                                     (PFLT_CONTEXT *)&oldStreamContext);

        if (!NT_SUCCESS(status))
        {

            if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED)
            {

                //
                //  Race condition. Someone has set a context after we queried it.
                //  Use the already set context instead
                //
                DbgPrint("Race Condition: Stream context already defined");

                FltReleaseContext(streamContext);

                streamContext = oldStreamContext;
            }
            else
            {
                DbgPrint("FltSetStreamContext failed: 0x%x", status);
                goto Cleanup;
            }
        }
    }
    else if (!NT_SUCCESS(status))
    {
        DbgPrint("FltGetStreamContext failed: 0x%x", status);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    //  If successfully opened a file with the desired access matching
    //  the "exclusive write" from a TxF point of view, we can guarantee that
    //  if previous transaction context exists, it must have been comitted
    //  or rollbacked.
    //

    if (FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
               FILE_WRITE_DATA | FILE_APPEND_DATA |
                   DELETE | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA |
                   WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY))
    {

        //
        //  Either this file is opened in a transaction context or not,
        //  we need to process the previous transaction if it exists.
        //  ProcessTransactions(...) handles these cases.
        //

        status = ProcessTransactions(FltObjects, streamContext);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("ProcessPreviousTransaction failed: 0x%x", status);
            goto Cleanup;
        }

        inTransaction = (FltObjects->Transaction != NULL);
    }

    if (IsFileNeedScan(streamContext))
    {
        status = PrepareScan(Data, FltObjects, Data->Iopb->MajorFunction, inTransaction, streamContext);
        if (!NT_SUCCESS(status) || (STATUS_TIMEOUT == status))
        {
            DbgPrint("Scan has failed: 0x%x", status);
            goto Cleanup;
        }
    }

    //
    // If needed, update the stream context with the latest revision
    // numbers that correspond to the verion just scanned
    //

    if (IsFileInfected(streamContext))
    {
        if (BLOCK_INFECTED)
        {
            //  If the file is infected, deny the access.
            DoCancelFileOpen(Data, FltObjects, STATUS_VIRUS_INFECTED);
        }
        //
        // TODO: If the scan timed-out or scan was failed, we let the create succeed, and it may cause security hole;
        goto Cleanup;
    }
    //TODO: remove goto Cleanup
Cleanup:

    FltReleaseContext(streamContext);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

/*++

The FLT callback PFLT_TRANSACTION_NOTIFICATION_CALLBACK
Arguments:
	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure
	TransactionContext - Pointer to the minifilter driver's transaction contextset at PostCreate.
	TransactionNotification - Specifies the type of notifications that the filter manager is sending to the minifilter driver.

Return Value:
	STATUS_SUCCESS - the driver is finished with the transaction. This is a success code.
	STATUS_PENDING - the driver is not yet finished with the transaction. This is a success code.
--*/

NTSTATUS TrNotificationCallback(_Unreferenced_parameter_ PCFLT_RELATED_OBJECTS FltObjects, _In_ PFLT_CONTEXT TransactionContext, _In_ ULONG TransactionNotification)
{
    PMW_TRANSACTION transactionContext = (PMW_TRANSACTION)TransactionContext;
    PAGED_CODE();
    UNREFERENCED_PARAMETER(FltObjects);

    if (NULL != transactionContext)
    {
        if (FlagOn(TransactionNotification, TRANSACTION_NOTIFY_COMMIT_FINALIZE))
        {
            return ProcessTransactionResult(transactionContext, TransactionOutcomeCommitted);
        }
        return ProcessTransactionResult(transactionContext, TransactionOutcomeAborted);
    }

    return STATUS_SUCCESS;
}

/*++
This is the registered cancel callback function in FLT_REGISTRATION. It would be invoked by the file system if it decides to abort the scan.

Note: This routine may be called before FltCreateSectionForDataScan returns.
This means the SectionHandle and SectionObject may not yet be set in the SectionContext. We can't take a dependency on these being set before needing to abort the scan.

Arguments:
	Instance - Opaque filter pointer for the caller. This parameter is required and cannot be NULL.
	Context - The section context.

	Data - Pointer to the filter callbackData that is passed to us.

Return Value:
	The status of this operation.

--*/
NTSTATUS ScanAbortCallback(_Unreferenced_parameter_ PFLT_INSTANCE Instance, _In_ PFLT_CONTEXT Context, _Unreferenced_parameter_ PFLT_CALLBACK_DATA Data)
{
    PMW_FILE_SECTION_CONTEXT sectionCtx = (PMW_FILE_SECTION_CONTEXT)Context;
    PAGED_CODE();

    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Data);

    if (NULL == sectionCtx)
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (sectionCtx->CancelableOnConflictingIo)
    {
        sectionCtx->ScanAborted = TRUE;
    }
    return STATUS_SUCCESS;
}

BOOLEAN IsVolumeOnCsvDisk(_In_ PFLT_VOLUME Volume)
{

    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN retValue = FALSE;
    PDEVICE_OBJECT disk = NULL, refDeviceObject = NULL;
    PIRP irp;
    IO_STATUS_BLOCK iosb;
    ULONG controlCode = IOCTL_DISK_GET_CLUSTER_INFO;
    DISK_CLUSTER_INFO outBuf;
    KEVENT event;

    PAGED_CODE();

    status = FltGetDiskDeviceObject(Volume, &disk);
    if (!NT_SUCCESS(status))
    {
        DbgPrint(" FltGetDiskDeviceObject failed: 0x%x", status);
        goto Cleanup;
    }

    refDeviceObject = IoGetAttachedDeviceReference(disk);

    iosb.Information = 0;
    RtlZeroMemory(&outBuf, sizeof(outBuf));
    KeInitializeEvent(&event, NotificationEvent, FALSE);

    irp = IoBuildDeviceIoControlRequest(controlCode,
                                        refDeviceObject,
                                        NULL,
                                        0,
                                        &outBuf,
                                        sizeof(outBuf),
                                        FALSE,
                                        &event,
                                        &iosb);
    if (irp == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DbgPrint("Failed to allocate Irp: 0x%x", status);
        goto Cleanup;
    }

    status = IoCallDriver(refDeviceObject, irp);
    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    retValue = FlagOn(outBuf.Flags, DISK_CLUSTER_FLAG_CSV) ? TRUE : FALSE;
    if (FlagOn(outBuf.Flags, DISK_CLUSTER_FLAG_CSV) && FlagOn(outBuf.Flags, DISK_CLUSTER_FLAG_IN_MAINTENANCE))
    {
        //
        // A CSV disk can be in maintenance mode. When in maintenance
        // mode the CSV namespace is no longer exposed across the
        // entire cluster but instead only exposed on the single node
        // where the NTFS volume is exposed. In this case the filter
        // should treat the volume as it would any other NTFS volume
        //
        retValue = FALSE;
    }
Cleanup:

    if (refDeviceObject)
    {
        KeEnterCriticalRegion();
        ObDereferenceObject(refDeviceObject);
        refDeviceObject = NULL;
        KeLeaveCriticalRegion();
    }

    if (disk)
    {
        ObDereferenceObject(disk);
        disk = NULL;
    }

    return retValue;
}

/*++
Checks if data stream is alternate or not.
--*/
BOOLEAN IsStreamAlternate(_Inout_ PFLT_CALLBACK_DATA Data)
{
    NTSTATUS status;
    BOOLEAN alternate = FALSE;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PAGED_CODE();

    do
    {
        status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &nameInfo);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        status = FltParseFileNameInformation(nameInfo);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        alternate = (nameInfo->Stream.Length > 0);
    } while (0);
    if (nameInfo != NULL)
    {
        FltReleaseFileNameInformation(nameInfo);
        nameInfo = NULL;
    }
    return alternate;
}

/*++
Checks if file is encrypted.
NON PAGED!
--*/
NTSTATUS IsFileEncrypted(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject, _Out_ PBOOLEAN Encrypted)
{
    NTSTATUS status = STATUS_SUCCESS;
    FILE_BASIC_INFORMATION basicInfo;

    status = FltQueryInformationFile(Instance, FileObject, &basicInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation, NULL);
    if (NT_SUCCESS(status))
    {
        *Encrypted = BooleanFlagOn(basicInfo.FileAttributes, FILE_ATTRIBUTE_ENCRYPTED);
    }
    return status;
}

/*++
Checks if object belongs to CSVFS
--*/

NTSTATUS CheckForCsvfs(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    NTSTATUS status;
    PMW_INSTANCE_CONTEXT instanceContext = NULL;
    UNREFERENCED_PARAMETER(Data);
    PAGED_CODE();

    status = FltGetInstanceContext(FltObjects->Instance, (PFLT_CONTEXT*)&instanceContext);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("FltGetInstanceContext failed %x", status);
        return status;
    }
    if (instanceContext->VolumeFSType == FLT_FSTYPE_CSVFS)
    {
        status = STATUS_NOT_SUPPORTED;
    }
    FltReleaseContext(instanceContext);
    return status;
}

/*++

Check if there is a CSVFS downlevel ECP attached.

Return Value:

TRUE - CSVFS downlevel ECP is present
FALSE - CSVFS downlevel ECP is not present or an error occured
--*/

BOOLEAN CheckForCsvDlEcp(_In_ PFLT_FILTER Filter, _In_ PFLT_CALLBACK_DATA Data)
{
    NTSTATUS status;
    PECP_LIST ecpList;
    PVOID ecpContext;
    PAGED_CODE();
    status = FltGetEcpListFromCallbackData(Filter, Data, &ecpList);

    if (NT_SUCCESS(status) && (ecpList != NULL))
    {
        status = FltFindExtraCreateParameter(Filter, ecpList, &GUID_ECP_CSV_DOWN_LEVEL_OPEN, &ecpContext, NULL);
        if (NT_SUCCESS(status))
        {
            return TRUE;
        }
    }
    return FALSE;
}

/*++
Check if this data stream is a prefetch ECP

Return Value:

TRUE - This data stream is alternate.
FALSE - This data stream is NOT alternate.
--*/
BOOLEAN CheckForPrefetchEcp(_In_ PFLT_FILTER Filter, _In_ PFLT_CALLBACK_DATA Data)
{
    NTSTATUS status;
    PECP_LIST ecpList;
    PVOID ecpContext;
    PAGED_CODE();
    status = FltGetEcpListFromCallbackData(Filter, Data, &ecpList);
    if (NT_SUCCESS(status) && (ecpList != NULL))
    {
        status = FltFindExtraCreateParameter(Filter, ecpList, &GUID_ECP_PREFETCH_OPEN, &ecpContext, NULL);
        if (NT_SUCCESS(status))
        {
            if (!FltIsEcpFromUserMode(Filter, ecpContext))
            {
                return TRUE;
            }
        }
    }
    return FALSE;
}

NTSTATUS GetTransactionContext(_In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_ PMW_TRANSACTION *TransactionContext)
{
    NTSTATUS status;
    PMW_TRANSACTION transactionContext = NULL;
    PMW_TRANSACTION oldTransactionContext = NULL;
    PERESOURCE pResource = NULL;

    PAGED_CODE();
    status = FltGetTransactionContext(FltObjects->Instance, FltObjects->Transaction, (PFLT_CONTEXT*)&transactionContext);
    if (NT_SUCCESS(status))
    {
        *TransactionContext = transactionContext;
        return STATUS_SUCCESS;
    }

    if (status != STATUS_NOT_FOUND)
    {
        DbgPrint("Failed to find transaction context: 0x%x", status);
        return status;
    }

    //  Allocate the resource
    pResource = DoAllocateResource();
    if (NULL == pResource)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //  Allocate a transaction context.
    status = FltAllocateContext(Globals.Filter, FLT_TRANSACTION_CONTEXT, sizeof(MW_TRANSACTION), PagedPool, (PFLT_CONTEXT*)&transactionContext);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Failed to  allocate transaction context: 0x%x", status);
        DoFreeResource(pResource);
        return status;
    }
    FLT_ASSERTMSG("Transaction object pointer is not supposed to be NULL !\n", FltObjects->Transaction != NULL);

    //
    //  Initialization of transaction context.
    //  The reason we allocate eResource seperately is because
    //  eResource has to be allocated in the non-paged pool.
    RtlZeroMemory(transactionContext, sizeof(MW_TRANSACTION));
    transactionContext->Resource = pResource;
    ObReferenceObject(FltObjects->Transaction);
    transactionContext->Transaction = FltObjects->Transaction;
    InitializeListHead(&transactionContext->ScListHead);
    ExInitializeResourceLite(transactionContext->Resource);
    status = FltSetTransactionContext(FltObjects->Instance, FltObjects->Transaction, FLT_SET_CONTEXT_KEEP_IF_EXISTS, transactionContext, (PFLT_CONTEXT*)&oldTransactionContext);

    if (NT_SUCCESS(status))
    {
        *TransactionContext = transactionContext;
        return STATUS_SUCCESS;
    }

    FltReleaseContext(transactionContext);

    if (status != STATUS_FLT_CONTEXT_ALREADY_DEFINED)
    {
        DbgPrint("Failed to set transaction context: 0x%x", status);
        return status;
    }

    if (NULL == oldTransactionContext)
    {
        DbgPrint("Failed to set old transaction context: 0x%x", status);
        return status;
    }
    *TransactionContext = oldTransactionContext;
    return STATUS_SUCCESS;
}

/*++
Creates new file stream context

Return Value:
The status of this operation.
--*/
NTSTATUS CreateFileStreamContext(_In_ PFLT_FILTER Filter, _Outptr_ PMW_STREAM_CONTEXT *StreamContext)
{
    NTSTATUS status;
    PKEVENT event = NULL;
    PMW_STREAM_CONTEXT streamContext;

    PAGED_CODE();
    event = DoAllocateKevent();
    if (NULL == event)
    {

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = FltAllocateContext(Filter, FLT_STREAM_CONTEXT, sizeof(MW_STREAM_CONTEXT), PagedPool, (PFLT_CONTEXT*)&streamContext);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Failed to allocate stream context: 0x%x", status);
        DoFreeKevent(event);
        return status;
    }

    RtlZeroMemory(streamContext, sizeof(MW_STREAM_CONTEXT));
    streamContext->ScanCompleteEvent = event;
    KeInitializeEvent(streamContext->ScanCompleteEvent, SynchronizationEvent, TRUE);
    SetContextFlagModified(&(streamContext->FinalState));
    SetContextFlagModified(&(streamContext->TxState));
    *StreamContext = streamContext;
    return STATUS_SUCCESS;
}

/*++
Creates new stream handle context

Return Value:
The status of this operation.
--*/
NTSTATUS CreateStreamHandleContext(_In_ PFLT_FILTER Filter, _Outptr_ PMW_STREAMHANDLE *StreamHandleContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    PMW_STREAMHANDLE streamHandleContext = NULL;

    PAGED_CODE();
    status = FltAllocateContext(Filter, FLT_STREAMHANDLE_CONTEXT, sizeof(MW_STREAMHANDLE), PagedPool, (PFLT_CONTEXT*)&streamHandleContext);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Failed to allocate stream handle context: 0x%x", status);
        return status;
    }
    RtlZeroMemory(streamHandleContext, sizeof(MW_STREAMHANDLE));
    *StreamHandleContext = streamHandleContext;
    return STATUS_SUCCESS;
}

/*++
cleanup callback from FLT_STREAM_CONTEXT
description: TBD
--*/
VOID StreamContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType)
{
    PMW_STREAM_CONTEXT streamContext = (PMW_STREAM_CONTEXT)Context;
    UNREFERENCED_PARAMETER(ContextType);
    PAGED_CODE();
    DoFreeKevent(streamContext->ScanCompleteEvent);
}

/*++
cleanup callback from FLT_TRANSACTION_CONTEXT
description: TBD
--*/
VOID TransactionContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType)
{
    PMW_TRANSACTION transactionContext = (PMW_TRANSACTION)Context;
    UNREFERENCED_PARAMETER(ContextType);
    PAGED_CODE();
    ExDeleteResourceLite(transactionContext->Resource);
    DoFreeResource(transactionContext->Resource);
    transactionContext->Resource = NULL;
    ObDereferenceObject(transactionContext->Transaction);
    transactionContext->Transaction = NULL;
}

/*++
Unused at the moment
--*/
VOID SectionContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ContextType);
}

/*++
Unused at the moment
--*/
VOID InstanceContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ContextType);
    PAGED_CODE();
}
