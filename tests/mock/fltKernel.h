//mocking file for ftpKernel.h!!!
#pragma once

typedef struct _LIST_ENTRY {
	struct _LIST_ENTRY *Flink;
	struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef void VOID;
#define CONST               const
typedef void* PVOID;
typedef char CHAR;
typedef long LONG;
typedef long long LONGLONG;
typedef unsigned char UCHAR;
typedef unsigned short USHORT;
typedef wchar_t WCHAR;
typedef USHORT* PWCH;
typedef CHAR* PCHAR;
typedef UCHAR BOOLEAN;           // winnt
typedef BOOLEAN *PBOOLEAN;       // winnt
typedef void *HANDLE;
typedef unsigned long ULONG;
typedef unsigned long long ULONGLONG;
typedef const CHAR *LPCSTR, *PCSTR;
typedef ULONG *PULONG;
typedef LONGLONG *PLONGLONG;
typedef ULONGLONG *PULONGLONG;

typedef struct _FILE_ID_128 {                               // winnt
	UCHAR Identifier[16];                                   // winnt
} FILE_ID_128, *PFILE_ID_128;                               // winnt

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWCH   Buffer;
} UNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
typedef struct _KTRANSACTION
{
	int unused;
} KTRANSACTION, *PKTRANSACTION;

typedef struct _ERESOURCE
{
	int unused;
} ERESOURCE, *PERESOURCE;

typedef struct _KEVENT
{
	int unused;
} KEVENT, *PKEVENT;

#define UNREFERENCED_PARAMETER(x)
#define PAGED_CODE()
#define FLT_ASSERTMSG(_m, _e)
#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (PCHAR)(address) - \
                                                  (ULONG_PTR)(&((type *)0)->field)))

typedef struct _FLT_FILTER *PFLT_FILTER;
typedef struct _FLT_VOLUME *PFLT_VOLUME;
typedef struct _FLT_INSTANCE *PFLT_INSTANCE;


typedef enum _FLT_FILESYSTEM_TYPE {

	FLT_FSTYPE_UNKNOWN,         //an UNKNOWN file system type
	FLT_FSTYPE_RAW,             //Microsoft's RAW file system       (\FileSystem\RAW)
	FLT_FSTYPE_NTFS,            //Microsoft's NTFS file system      (\FileSystem\Ntfs)
	FLT_FSTYPE_FAT,             //Microsoft's FAT file system       (\FileSystem\Fastfat)
	FLT_FSTYPE_CDFS,            //Microsoft's CDFS file system      (\FileSystem\Cdfs)
	FLT_FSTYPE_UDFS,            //Microsoft's UDFS file system      (\FileSystem\Udfs)
	FLT_FSTYPE_LANMAN,          //Microsoft's LanMan Redirector     (\FileSystem\MRxSmb)
	FLT_FSTYPE_WEBDAV,          //Microsoft's WebDav redirector     (\FileSystem\MRxDav)
	FLT_FSTYPE_RDPDR,           //Microsoft's Terminal Server redirector    (\Driver\rdpdr)
	FLT_FSTYPE_NFS,             //Microsoft's NFS file system       (\FileSystem\NfsRdr)
	FLT_FSTYPE_MS_NETWARE,      //Microsoft's NetWare redirector    (\FileSystem\nwrdr)
	FLT_FSTYPE_NETWARE,         //Novell's NetWare redirector
	FLT_FSTYPE_BSUDF,           //The BsUDF CD-ROM driver           (\FileSystem\BsUDF)
	FLT_FSTYPE_MUP,             //Microsoft's Mup redirector        (\FileSystem\Mup)
	FLT_FSTYPE_RSFX,            //Microsoft's WinFS redirector      (\FileSystem\RsFxDrv)
	FLT_FSTYPE_ROXIO_UDF1,      //Roxio's UDF writeable file system (\FileSystem\cdudf_xp)
	FLT_FSTYPE_ROXIO_UDF2,      //Roxio's UDF readable file system  (\FileSystem\UdfReadr_xp)
	FLT_FSTYPE_ROXIO_UDF3,      //Roxio's DVD file system           (\FileSystem\DVDVRRdr_xp)
	FLT_FSTYPE_TACIT,           //Tacit FileSystem                  (\Device\TCFSPSE)
	FLT_FSTYPE_FS_REC,          //Microsoft's File system recognizer (\FileSystem\Fs_rec)
	FLT_FSTYPE_INCD,            //Nero's InCD file system           (\FileSystem\InCDfs)
	FLT_FSTYPE_INCD_FAT,        //Nero's InCD FAT file system       (\FileSystem\InCDFat)
	FLT_FSTYPE_EXFAT,           //Microsoft's EXFat FILE SYSTEM     (\FileSystem\exfat)
	FLT_FSTYPE_PSFS,            //PolyServ's file system            (\FileSystem\psfs)
	FLT_FSTYPE_GPFS,            //IBM General Parallel File System  (\FileSystem\gpfs)
	FLT_FSTYPE_NPFS,            //Microsoft's Named Pipe file system(\FileSystem\npfs)
	FLT_FSTYPE_MSFS,            //Microsoft's Mailslot file system  (\FileSystem\msfs)
	FLT_FSTYPE_CSVFS,           //Microsoft's Cluster Shared Volume file system  (\FileSystem\csvfs)
	FLT_FSTYPE_REFS,            //Microsoft's ReFS file system      (\FileSystem\Refs or \FileSystem\Refsv1)
	FLT_FSTYPE_OPENAFS          //OpenAFS file system               (\Device\AFSRedirector)

} FLT_FILESYSTEM_TYPE, *PFLT_FILESYSTEM_TYPE;


typedef UNICODE_STRING *PUNICODE_STRING;

typedef ULONG FLT_INSTANCE_SETUP_FLAGS;
typedef ULONG FLT_FILTER_UNLOAD_FLAGS;
typedef ULONG FLT_INSTANCE_QUERY_TEARDOWN_FLAGS;
typedef ULONG FLT_INSTANCE_TEARDOWN_FLAGS;
typedef PVOID PFLT_CONTEXT;
typedef ULONG FLT_POST_OPERATION_FLAGS;
typedef __int64 LONG_PTR, *PLONG_PTR;
typedef unsigned __int64 ULONG_PTR, *PULONG_PTR;

typedef ULONG_PTR SIZE_T, *PSIZE_T;
typedef LONG_PTR SSIZE_T, *PSSIZE_T;

typedef ULONG ACCESS_MASK;

typedef struct _FILE_OBJECT *PFILE_OBJECT;
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth
#define STATUS_FLT_DO_NOT_ATTACH         ((NTSTATUS)0xC01C000FL)


#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014

#define STANDARD_RIGHTS_ALL              (0x001F0000L)
#define FLT_PORT_CONNECT        0x0001
#define FLT_PORT_ALL_ACCESS     (FLT_PORT_CONNECT | STANDARD_RIGHTS_ALL)
typedef struct _IO_STATUS_BLOCK {
	NTSTATUS Status;

	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _FLT_CALLBACK_DATA {
	IO_STATUS_BLOCK IoStatus;
} FLT_CALLBACK_DATA, *PFLT_CALLBACK_DATA;

typedef struct _FLT_RELATED_OBJECTS {

	USHORT Size;
	USHORT TransactionContext;            //TxF mini-version
	PFLT_FILTER Filter;
	PFLT_VOLUME Volume;
	PFLT_INSTANCE Instance;
	PFILE_OBJECT  FileObject;
	PKTRANSACTION Transaction;

} FLT_RELATED_OBJECTS, *PFLT_RELATED_OBJECTS;

typedef const struct _FLT_RELATED_OBJECTS *PCFLT_RELATED_OBJECTS;

typedef struct _TRANSACTION_BASIC_INFORMATION {
	GUID    TransactionId;
	ULONG   State;
	ULONG   Outcome;
} TRANSACTION_BASIC_INFORMATION, *PTRANSACTION_BASIC_INFORMATION;

typedef PVOID PSECURITY_DESCRIPTOR;
typedef ULONG FLT_OPERATION_REGISTRATION_FLAGS;

typedef enum _FLT_PREOP_CALLBACK_STATUS {

	FLT_PREOP_SUCCESS_WITH_CALLBACK,
	FLT_PREOP_SUCCESS_NO_CALLBACK,
	FLT_PREOP_PENDING,
	FLT_PREOP_DISALLOW_FASTIO,
	FLT_PREOP_COMPLETE,
	FLT_PREOP_SYNCHRONIZE


} FLT_PREOP_CALLBACK_STATUS, *PFLT_PREOP_CALLBACK_STATUS;


typedef enum _FLT_POSTOP_CALLBACK_STATUS {

	FLT_POSTOP_FINISHED_PROCESSING,
	FLT_POSTOP_MORE_PROCESSING_REQUIRED

} FLT_POSTOP_CALLBACK_STATUS, *PFLT_POSTOP_CALLBACK_STATUS;

typedef FLT_PREOP_CALLBACK_STATUS
(*PFLT_PRE_OPERATION_CALLBACK) (
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Outptr_result_maybenull_ PVOID *CompletionContext
	);
typedef ULONG FLT_POST_OPERATION_FLAGS;

typedef FLT_POSTOP_CALLBACK_STATUS
(*PFLT_POST_OPERATION_CALLBACK) (
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

typedef struct _FLT_OPERATION_REGISTRATION {

	UCHAR MajorFunction;
	FLT_OPERATION_REGISTRATION_FLAGS Flags;
	PFLT_PRE_OPERATION_CALLBACK PreOperation;
	PFLT_POST_OPERATION_CALLBACK PostOperation;

	PVOID Reserved1;

} FLT_OPERATION_REGISTRATION, *PFLT_OPERATION_REGISTRATION;

typedef struct _DRIVER_OBJECT {
	/*CSHORT Type;
	CSHORT Size;

	//
	// The following links all of the devices created by a single driver
	// together on a list, and the Flags word provides an extensible flag
	// location for driver objects.
	//

	PDEVICE_OBJECT DeviceObject;
	ULONG Flags;

	//
	// The following section describes where the driver is loaded.  The count
	// field is used to count the number of times the driver has had its
	// registered reinitialization routine invoked.
	//

	PVOID DriverStart;
	ULONG DriverSize;
	PVOID DriverSection;
	PDRIVER_EXTENSION DriverExtension;

	//
	// The driver name field is used by the error log thread
	// determine the name of the driver that an I/O request is/was bound.
	//

	UNICODE_STRING DriverName;

	//
	// The following section is for registry support.  Thise is a pointer
	// to the path to the hardware information in the registry
	//

	PUNICODE_STRING HardwareDatabase;

	//
	// The following section contains the optional pointer to an array of
	// alternate entry points to a driver for "fast I/O" support.  Fast I/O
	// is performed by invoking the driver routine directly with separate
	// parameters, rather than using the standard IRP call mechanism.  Note
	// that these functions may only be used for synchronous I/O, and when
	// the file is cached.
	//

	PFAST_IO_DISPATCH FastIoDispatch;

	//
	// The following section describes the entry points to this particular
	// driver.  Note that the major function dispatch table must be the last
	// field in the object so that it remains extensible.
	//

	PDRIVER_INITIALIZE DriverInit;
	PDRIVER_STARTIO DriverStartIo;
	PDRIVER_UNLOAD DriverUnload;
	PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];*/

} DRIVER_OBJECT;
typedef struct _DRIVER_OBJECT *PDRIVER_OBJECT;


#define DEVICE_TYPE ULONG

typedef enum _POOL_TYPE {
	NonPagedPool,
	NonPagedPoolExecute = NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed = NonPagedPool + 2,
	DontUseThisType,
	NonPagedPoolCacheAligned = NonPagedPool + 4,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
	MaxPoolType,

	//
	// Define base types for NonPaged (versus Paged) pool, for use in cracking
	// the underlying pool type.
	//

	NonPagedPoolBase = 0,
	NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
	NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
	NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,

	//
	// Note these per session types are carefully chosen so that the appropriate
	// masking still applies as well as MaxPoolType above.
	//

	NonPagedPoolSession = 32,
	PagedPoolSession = NonPagedPoolSession + 1,
	NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
	DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
	NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
	PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
	NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,

	NonPagedPoolNx = 512,
	NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
	NonPagedPoolSessionNx = NonPagedPoolNx + 32,

} POOL_TYPE;

typedef USHORT FLT_CONTEXT_TYPE;

#define FLT_VOLUME_CONTEXT          0x0001
#define FLT_INSTANCE_CONTEXT        0x0002
#define FLT_FILE_CONTEXT            0x0004
#define FLT_STREAM_CONTEXT          0x0008
#define FLT_STREAMHANDLE_CONTEXT    0x0010
#define FLT_TRANSACTION_CONTEXT     0x0020
#define FLT_SECTION_CONTEXT         0x0040
#define FLT_CONTEXT_END             0xffff

typedef USHORT FLT_CONTEXT_REGISTRATION_FLAGS;
typedef VOID
(*PFLT_CONTEXT_CLEANUP_CALLBACK) (
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
	);

typedef PVOID
(*PFLT_CONTEXT_ALLOCATE_CALLBACK)(
	_In_ POOL_TYPE PoolType,
	_In_ SIZE_T Size,
	_In_ FLT_CONTEXT_TYPE ContextType
	);

typedef VOID
(*PFLT_CONTEXT_FREE_CALLBACK)(
	_In_ PVOID Pool,
	_In_ FLT_CONTEXT_TYPE ContextType
	);


typedef struct _FLT_CONTEXT_REGISTRATION {

	//
	//  Identifies the type of this context
	//

	FLT_CONTEXT_TYPE ContextType;

	//
	//  Local flags
	//

	FLT_CONTEXT_REGISTRATION_FLAGS Flags;

	//
	//  Routine to call to cleanup the context before it is deleted.
	//  This may be NULL if not cleanup is needed.
	//

	PFLT_CONTEXT_CLEANUP_CALLBACK ContextCleanupCallback;

	//
	//  Defines the size & pool tag the mini-filter wants for the given context.
	//  FLT_VARIABLE_SIZED_CONTEXTS may be specified for the size if variable
	//  sized contexts are used.  A size of zero is valid.  If an empty pooltag
	//  value is specified, the FLTMGR will use a context type specific tag.
	//
	//  If an explicit size is specified, the FLTMGR internally optimizes the
	//  allocation of that entry.
	//
	//  NOTE:  These fields are ignored if Allocate & Free routines are
	//         specifed.
	//

	SIZE_T Size;
	ULONG PoolTag;

	//
	//  Specifies the ALLOCATE and FREE routines that should be used
	//  when allocating a context for this mini-filter.
	//
	//  NOTE: The above size & PoolTag fields are ignored when these routines
	//        are defined.
	//

	PFLT_CONTEXT_ALLOCATE_CALLBACK ContextAllocateCallback;
	PFLT_CONTEXT_FREE_CALLBACK ContextFreeCallback;

	//
	//  Reserved for future expansion
	//

	PVOID Reserved1;

} FLT_CONTEXT_REGISTRATION, *PFLT_CONTEXT_REGISTRATION;

typedef ULONG FLT_REGISTRATION_FLAGS;

typedef NTSTATUS
( *PFLT_FILTER_UNLOAD_CALLBACK) (
	FLT_FILTER_UNLOAD_FLAGS Flags
	);

typedef NTSTATUS
(*PFLT_INSTANCE_SETUP_CALLBACK) (
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
	);
typedef ULONG FLT_INSTANCE_QUERY_TEARDOWN_FLAGS;
typedef NTSTATUS
(*PFLT_INSTANCE_QUERY_TEARDOWN_CALLBACK) (
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
	);
typedef ULONG FLT_INSTANCE_TEARDOWN_FLAGS;
typedef VOID
(*PFLT_INSTANCE_TEARDOWN_CALLBACK) (
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
	);

typedef ULONG FLT_FILE_NAME_OPTIONS;
typedef struct _FLT_NAME_CONTROL {

	//
	//  The unicode string where the name should be set.
	//

	UNICODE_STRING Name;

} FLT_NAME_CONTROL, *PFLT_NAME_CONTROL;

typedef NTSTATUS
(*PFLT_GENERATE_FILE_NAME) (
	_In_ PFLT_INSTANCE Instance,
	_In_ PFILE_OBJECT FileObject,
	_In_opt_ PFLT_CALLBACK_DATA CallbackData,
	_In_ FLT_FILE_NAME_OPTIONS NameOptions,
	_Out_ PBOOLEAN CacheFileNameInformation,
	_Out_ PFLT_NAME_CONTROL FileName
	);

typedef ULONG FLT_NORMALIZE_NAME_FLAGS;

typedef struct _FILE_NAMES_INFORMATION {
	ULONG NextEntryOffset;
	ULONG FileIndex;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

#define FLT_REGISTRATION_VERSION_0203  0x0203
#define FLT_REGISTRATION_VERSION  0x0203

typedef NTSTATUS
(*PFLT_NORMALIZE_NAME_COMPONENT) (
	_In_ PFLT_INSTANCE Instance,
	_In_ PCUNICODE_STRING ParentDirectory,
	_In_ USHORT VolumeNameLength,
	_In_ PCUNICODE_STRING Component,
	_Out_writes_bytes_(ExpandComponentNameLength) PFILE_NAMES_INFORMATION ExpandComponentName,
	_In_ ULONG ExpandComponentNameLength,
	_In_ FLT_NORMALIZE_NAME_FLAGS Flags,
	_Inout_ PVOID *NormalizationContext
	);
typedef VOID
(*PFLT_NORMALIZE_CONTEXT_CLEANUP) (
	_In_opt_ PVOID *NormalizationContext
	);

typedef NTSTATUS
(*PFLT_TRANSACTION_NOTIFICATION_CALLBACK) (
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_CONTEXT TransactionContext,
	_In_ ULONG NotificationMask
	);
typedef NTSTATUS
(*PFLT_NORMALIZE_NAME_COMPONENT_EX) (
	_In_ PFLT_INSTANCE Instance,
	_In_ PFILE_OBJECT FileObject,
	_In_ PCUNICODE_STRING ParentDirectory,
	_In_ USHORT VolumeNameLength,
	_In_ PCUNICODE_STRING Component,
	_Out_writes_bytes_(ExpandComponentNameLength) PFILE_NAMES_INFORMATION ExpandComponentName,
	_In_ ULONG ExpandComponentNameLength,
	_In_ FLT_NORMALIZE_NAME_FLAGS Flags,
	_Inout_ PVOID *NormalizationContext
	);
typedef NTSTATUS
(*PFLT_SECTION_CONFLICT_NOTIFICATION_CALLBACK) (
	_In_ PFLT_INSTANCE Instance,
	_In_ PFLT_CONTEXT SectionContext,
	_In_ PFLT_CALLBACK_DATA Data
	);

typedef enum _FLT_SET_CONTEXT_OPERATION {

	//
	//  If a context already exists, replace with the given context.
	//  Return the old context.
	//

	FLT_SET_CONTEXT_REPLACE_IF_EXISTS,

	//
	//  If a context already exists, keep the old context and return an
	//  error status.  Return the old context (yes, we really do want to
	//  return the old context, the caller already has the new context).
	//  The context returned must later be released.
	//

	FLT_SET_CONTEXT_KEEP_IF_EXISTS

} FLT_SET_CONTEXT_OPERATION, *PFLT_SET_CONTEXT_OPERATION;


typedef struct _FLT_REGISTRATION {

	//
	//  The size, in bytes, of this registration structure.
	//

	USHORT Size;
	USHORT Version;

	//
	//  Flag values
	//

	FLT_REGISTRATION_FLAGS Flags;

	//
	//  Variable length array of routines that are used to manage contexts in
	//  the system.
	//

	CONST FLT_CONTEXT_REGISTRATION *ContextRegistration;

	//
	//  Variable length array of routines used for processing pre- and post-
	//  file system operations.
	//

	CONST FLT_OPERATION_REGISTRATION *OperationRegistration;

	//
	//  This is called before a filter is unloaded.  If an ERROR or WARNING
	//  status is returned then the filter is NOT unloaded.  A mandatory unload
	//  can not be failed.
	//
	//  If a NULL is specified for this routine, then the filter can never be
	//  unloaded.
	//

	PFLT_FILTER_UNLOAD_CALLBACK FilterUnloadCallback;

	//
	//  This is called to see if a filter would like to attach an instance
	//  to the given volume.  If an ERROR or WARNING status is returned, an
	//  attachment is not made.
	//
	//  If a NULL is specified for this routine, the attachment is always made.
	//

	PFLT_INSTANCE_SETUP_CALLBACK InstanceSetupCallback;

	//
	//  This is called to see if the filter wants to detach from the given
	//  volume.  This is only called for manual detach requests.  If an
	//  ERROR or WARNING status is returned, the filter is not detached.
	//
	//  If a NULL is specified for this routine, then instances can never be
	//  manually detached.
	//

	PFLT_INSTANCE_QUERY_TEARDOWN_CALLBACK InstanceQueryTeardownCallback;

	//
	//  This is called at the start of a filter detaching from a volume.
	//
	//  It is OK for this field to be NULL.
	//

	PFLT_INSTANCE_TEARDOWN_CALLBACK InstanceTeardownStartCallback;

	//
	//  This is called at the end of a filter detaching from a volume.  All
	//  outstanding operations have been completed by the time this routine
	//  is called.
	//
	//  It is OK for this field to be NULL.
	//

	PFLT_INSTANCE_TEARDOWN_CALLBACK InstanceTeardownCompleteCallback;

	//
	//  The following callbacks are provided by a filter only if it is
	//  interested in modifying the name space.
	//
	//  If NULL is specified for these callbacks, it is assumed that the
	//  filter would not affect the name being requested.
	//

	PFLT_GENERATE_FILE_NAME GenerateFileNameCallback;

	PFLT_NORMALIZE_NAME_COMPONENT NormalizeNameComponentCallback;

	PFLT_NORMALIZE_CONTEXT_CLEANUP NormalizeContextCleanupCallback;

	//
	//  The PFLT_NORMALIZE_NAME_COMPONENT_EX callback is also a name
	//  provider callback. It is not included here along with the
	//  other name provider callbacks to take care of the registration
	//  structure versioning issues.
	//

#if 1

	//
	//  This is called for transaction notifications received from the KTM
	//  when a filter has enlisted on that transaction.
	//

	PFLT_TRANSACTION_NOTIFICATION_CALLBACK TransactionNotificationCallback;

	//
	//  This is the extended normalize name component callback
	//  If a mini-filter provides this callback, then  this callback
	//  will be used as opposed to using PFLT_NORMALIZE_NAME_COMPONENT
	//
	//  The PFLT_NORMALIZE_NAME_COMPONENT_EX provides an extra parameter
	//  (PFILE_OBJECT) in addition to the parameters provided to
	//  PFLT_NORMALIZE_NAME_COMPONENT. A mini-filter may use this parameter
	//  to get to additional information like the TXN_PARAMETER_BLOCK.
	//
	//  A mini-filter that has no use for the additional parameter may
	//  only provide a PFLT_NORMALIZE_NAME_COMPONENT callback.
	//
	//  A mini-filter may provide both a PFLT_NORMALIZE_NAME_COMPONENT
	//  callback and a PFLT_NORMALIZE_NAME_COMPONENT_EX callback. The
	//  PFLT_NORMALIZE_NAME_COMPONENT_EX callback will be used by fltmgr
	//  versions that understand this callback (Vista RTM and beyond)
	//  and PFLT_NORMALIZE_NAME_COMPONENT callback will be used by fltmgr
	//  versions that do not understand the PFLT_NORMALIZE_NAME_COMPONENT_EX
	//  callback (prior to Vista RTM). This allows the same mini-filter
	//  binary to run with all versions of fltmgr.
	//

	PFLT_NORMALIZE_NAME_COMPONENT_EX NormalizeNameComponentExCallback;

#endif // FLT_MGR_LONGHORN

#if 1 //FLT_MGR_WIN8

	//
	//  This is called for IO failures due to the existence of sections
	//  when those sections are created through FltCreateSectionForDatascan.
	//

	PFLT_SECTION_CONFLICT_NOTIFICATION_CALLBACK SectionNotificationCallback;

#endif // FLT_MGR_WIN8

} FLT_REGISTRATION, *PFLT_REGISTRATION;



#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_OPERATION_END                        ((UCHAR)0x80)

#ifndef FORCEINLINE
#if (_MSC_VER >= 1200)
#define FORCEINLINE __forceinline
#else
#define FORCEINLINE __inline
#endif
#endif
#define _Unreferenced_parameter_
#define  _Flt_CompletionContext_Outptr_


FORCEINLINE LONG InterlockedExchange(
	_Inout_ _Interlocked_operand_ LONG volatile *Target,
	_In_ LONG Value
)
{
	LONG result = *Target;
	*Target = Value;
	return result;
}

typedef
NTSTATUS
DRIVER_INITIALIZE(
	_In_ struct _DRIVER_OBJECT *DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

#define FLT_ASSERT(x)
#define FALSE   0
#define TRUE    1	

PVOID ExAllocatePoolWithTag( _In_ POOL_TYPE PoolType, _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag);
VOID ExFreePoolWithTag(PVOID P, _In_ ULONG Tag);
VOID KeEnterCriticalRegion();
VOID KeLeaveCriticalRegion();
	
BOOLEAN ExAcquireResourceExclusiveLite( PERESOURCE Resource, BOOLEAN Wait );
VOID ExReleaseResourceLite( _Inout_ PERESOURCE Resource );


VOID FltCancelFileOpen( _In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject);

NTSTATUS FltAllocateContext(
	_In_ PFLT_FILTER Filter,
	_In_ FLT_CONTEXT_TYPE ContextType,
	_In_ SIZE_T ContextSize,
	_In_ POOL_TYPE PoolType,
	_Outptr_result_bytebuffer_(ContextSize) PFLT_CONTEXT *ReturnedContext
);


ULONG DbgPrint(PCSTR Format, ...);
#define RtlZeroMemory(Destination,Length) memset((Destination),0,(Length))

NTSTATUS
FltBuildDefaultSecurityDescriptor(
	_Outptr_ PSECURITY_DESCRIPTOR *SecurityDescriptor,
	_In_ ACCESS_MASK DesiredAccess
);