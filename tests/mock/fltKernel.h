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
typedef HANDLE* PHANDLE;
typedef unsigned long ULONG;
typedef unsigned long long ULONGLONG;
typedef const CHAR *LPCSTR, *PCSTR;
typedef ULONG *PULONG;
typedef LONGLONG *PLONGLONG;
typedef ULONGLONG *PULONGLONG;
typedef unsigned __int64 UINT_PTR, *PUINT_PTR;

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

typedef struct _KEVENT {
	int unused;
	
} KEVENT, *PKEVENT, *PRKEVENT;


typedef enum _EVENT_TYPE {
	NotificationEvent,
	SynchronizationEvent
} EVENT_TYPE;

typedef LONG KPRIORITY;


#define UNREFERENCED_PARAMETER(x)
#define PAGED_CODE()
#define FLT_ASSERT(x)
#define FALSE   0
#define TRUE    1	
#define ASSERT(x)
#define FLT_ASSERTMSG(_m, _e)

#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (PCHAR)(address) - \
                                                  (ULONG_PTR)(&((type *)0)->field)))


#ifndef FlagOn
#define FlagOn(_F,_SF)        ((_F) & (_SF))
#endif

#ifndef BooleanFlagOn
#define BooleanFlagOn(F,SF)   ((BOOLEAN)(((F) & (SF)) != 0))
#endif

#ifndef SetFlag
#define SetFlag(_F,_SF)       ((_F) |= (_SF))
#endif

#ifndef ClearFlag
#define ClearFlag(_F,_SF)     ((_F) &= ~(_SF))
#endif

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

typedef union _LARGE_INTEGER {
	LONGLONG QuadPart;
} LARGE_INTEGER;

typedef LARGE_INTEGER *PLARGE_INTEGER;
typedef PVOID PSECURITY_DESCRIPTOR;

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth
#define STATUS_FLT_DO_NOT_ATTACH         ((NTSTATUS)0xC01C000FL)
#define STATUS_FLT_NO_HANDLER_DEFINED    ((NTSTATUS)0xC01C0001L)
#define STATUS_FLT_CONTEXT_ALREADY_DEFINED ((NTSTATUS)0xC01C0002L)
#define STATUS_TIMEOUT                   ((NTSTATUS)0x00000102L)    // winnt
#define STATUS_VIRUS_INFECTED            ((NTSTATUS)0xC0000906L)
#define STATUS_INSUFFICIENT_RESOURCES    ((NTSTATUS)0xC000009AL)     // ntsubauth
#define STATUS_PENDING                   ((NTSTATUS)0x00000103L)    // winnt
#define STATUS_FLT_ALREADY_ENLISTED      ((NTSTATUS)0xC01C001BL)
#define STATUS_REPARSE                   ((NTSTATUS)0x00000104L)
#define STATUS_NOT_FOUND                 ((NTSTATUS)0xC0000225L)
#define STATUS_INVALID_PARAMETER_2       ((NTSTATUS)0xC00000F0L)
#define STATUS_NOT_SUPPORTED             ((NTSTATUS)0xC00000BBL)

typedef struct _DEVICE_OBJECT {
	//CSHORT Type;
	USHORT Size;
	LONG ReferenceCount;
	struct _DRIVER_OBJECT *DriverObject;
	struct _DEVICE_OBJECT *NextDevice;
	struct _DEVICE_OBJECT *AttachedDevice;
	struct _IRP *CurrentIrp;
	//PIO_TIMER Timer;
	ULONG Flags;                                // See above:  DO_...
	ULONG Characteristics;                      // See ntioapi:  FILE_...
												//volatile PVPB Vpb;
	PVOID DeviceExtension;
	//DEVICE_TYPE DeviceType;
	//CCHAR StackSize;
	union {
		LIST_ENTRY ListEntry;
		//WAIT_CONTEXT_BLOCK Wcb;
	} Queue;
	ULONG AlignmentRequirement;
	//KDEVICE_QUEUE DeviceQueue;
	//KDPC Dpc;

	//
	//  The following field is for exclusive use by the filesystem to keep
	//  track of the number of Fsp threads currently using the device
	//

	ULONG ActiveThreadCount;
	PSECURITY_DESCRIPTOR SecurityDescriptor;
	KEVENT DeviceLock;

	USHORT SectorSize;
	USHORT Spare1;

	struct _DEVOBJ_EXTENSION  *DeviceObjectExtension;
	PVOID  Reserved;

} DEVICE_OBJECT;

typedef struct _DEVICE_OBJECT *PDEVICE_OBJECT;
#define FILE_INVALID_FILE_ID               ((LONGLONG)-1LL) // winnt
typedef struct _FILE_OBJECT {
	//CSHORT Type;
	//CSHORT Size;
	PDEVICE_OBJECT DeviceObject;
	//PVPB Vpb;
	PVOID FsContext;
	PVOID FsContext2;
	//PSECTION_OBJECT_POINTERS SectionObjectPointer;
	PVOID PrivateCacheMap;
	NTSTATUS FinalStatus;
	struct _FILE_OBJECT *RelatedFileObject;
	BOOLEAN LockOperation;
	BOOLEAN DeletePending;
	BOOLEAN ReadAccess;
	BOOLEAN WriteAccess;
	BOOLEAN DeleteAccess;
	BOOLEAN SharedRead;
	BOOLEAN SharedWrite;
	BOOLEAN SharedDelete;
	ULONG Flags;
	UNICODE_STRING FileName;
	LARGE_INTEGER CurrentByteOffset;
	volatile ULONG Waiters;
	volatile ULONG Busy;
	PVOID LastLock;
	KEVENT Lock;
	KEVENT Event;
	//__volatile PIO_COMPLETION_CONTEXT CompletionContext;
	//KSPIN_LOCK IrpListLock;
	LIST_ENTRY IrpList;
	//__volatile PVOID FileObjectExtension;
} FILE_OBJECT;

typedef struct _FILE_OBJECT *PFILE_OBJECT;
typedef struct _OBJECT_TYPE *POBJECT_TYPE;




#define FILE_READ_DATA            ( 0x0001 )    // file & pipe
#define FILE_LIST_DIRECTORY       ( 0x0001 )    // directory

#define FILE_WRITE_DATA           ( 0x0002 )    // file & pipe
#define FILE_ADD_FILE             ( 0x0002 )    // directory

#define FILE_APPEND_DATA          ( 0x0004 )    // file
#define FILE_ADD_SUBDIRECTORY     ( 0x0004 )    // directory
#define FILE_CREATE_PIPE_INSTANCE ( 0x0004 )    // named pipe


#define FILE_READ_EA              ( 0x0008 )    // file & directory

#define FILE_WRITE_EA             ( 0x0010 )    // file & directory

#define FILE_EXECUTE              ( 0x0020 )    // file
#define FILE_TRAVERSE             ( 0x0020 )    // directory

#define FILE_DELETE_CHILD         ( 0x0040 )    // directory

#define FILE_READ_ATTRIBUTES      ( 0x0080 )    // all

#define FILE_WRITE_ATTRIBUTES     ( 0x0100 )    // all

#define FILE_DIRECTORY_FILE                     0x00000001


#define FILE_ATTRIBUTE_OFFLINE              0x00001000  
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  0x00002000  
#define FILE_ATTRIBUTE_ENCRYPTED            0x00004000  

#define SL_FORCE_ACCESS_CHECK           0x01
#define SL_OPEN_PAGING_FILE             0x02
#define SL_OPEN_TARGET_DIRECTORY        0x04
#define SL_STOP_ON_SYMLINK              0x08
#define SL_CASE_SENSITIVE               0x80
#define FO_VOLUME_OPEN                  0x00400000

#define DELETE                           (0x00010000L)
#define READ_CONTROL                     (0x00020000L)
#define WRITE_DAC                        (0x00040000L)
#define WRITE_OWNER                      (0x00080000L)
#define SYNCHRONIZE                      (0x00100000L)

#define STANDARD_RIGHTS_REQUIRED         (0x000F0000L)

#define STANDARD_RIGHTS_READ             (READ_CONTROL)
#define STANDARD_RIGHTS_WRITE            (READ_CONTROL)
#define STANDARD_RIGHTS_EXECUTE          (READ_CONTROL)

#define STANDARD_RIGHTS_ALL              (0x001F0000L)

#define SPECIFIC_RIGHTS_ALL              (0x0000FFFFL)

//
// AccessSystemAcl access type
//

#define ACCESS_SYSTEM_SECURITY           (0x01000000L)

//
// MaximumAllowed access type
//

#define MAXIMUM_ALLOWED                  (0x02000000L)

//
//  These are the generic rights.
//

#define GENERIC_READ                     (0x80000000L)
#define GENERIC_WRITE                    (0x40000000L)
#define GENERIC_EXECUTE                  (0x20000000L)
#define GENERIC_ALL                      (0x10000000L)

#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L


#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014

#define STANDARD_RIGHTS_ALL              (0x001F0000L)
#define FLT_PORT_CONNECT        0x0001
#define FLT_PORT_ALL_ACCESS     (FLT_PORT_CONNECT | STANDARD_RIGHTS_ALL)


#define TRANSACTION_NOTIFY_MASK                 0x3FFFFFFF
#define TRANSACTION_NOTIFY_PREPREPARE           0x00000001
#define TRANSACTION_NOTIFY_PREPARE              0x00000002
#define TRANSACTION_NOTIFY_COMMIT               0x00000004
#define TRANSACTION_NOTIFY_ROLLBACK             0x00000008
#define TRANSACTION_NOTIFY_PREPREPARE_COMPLETE  0x00000010
#define TRANSACTION_NOTIFY_PREPARE_COMPLETE     0x00000020
#define TRANSACTION_NOTIFY_COMMIT_COMPLETE      0x00000040
#define TRANSACTION_NOTIFY_ROLLBACK_COMPLETE    0x00000080
#define TRANSACTION_NOTIFY_RECOVER              0x00000100
#define TRANSACTION_NOTIFY_SINGLE_PHASE_COMMIT  0x00000200
#define TRANSACTION_NOTIFY_DELEGATE_COMMIT      0x00000400
#define TRANSACTION_NOTIFY_RECOVER_QUERY        0x00000800
#define TRANSACTION_NOTIFY_ENLIST_PREPREPARE    0x00001000
#define TRANSACTION_NOTIFY_LAST_RECOVER         0x00002000
#define TRANSACTION_NOTIFY_INDOUBT              0x00004000
#define TRANSACTION_NOTIFY_PROPAGATE_PULL       0x00008000
#define TRANSACTION_NOTIFY_PROPAGATE_PUSH       0x00010000
#define TRANSACTION_NOTIFY_MARSHAL              0x00020000
#define TRANSACTION_NOTIFY_ENLIST_MASK          0x00040000
#define TRANSACTION_NOTIFY_RM_DISCONNECTED      0x01000000
#define TRANSACTION_NOTIFY_TM_ONLINE            0x02000000
#define TRANSACTION_NOTIFY_COMMIT_REQUEST       0x04000000
#define TRANSACTION_NOTIFY_PROMOTE              0x08000000
#define TRANSACTION_NOTIFY_PROMOTE_NEW          0x10000000
#define TRANSACTION_NOTIFY_REQUEST_OUTCOME      0x20000000
//
//  Note that this flag is not included in the TRANSACTION_NOTIFY_MASK.
//  The reason being that KTM does not understand this flag yet. This
//  flag is strictly for the use of filter manager. In fact we mask it
//  out before enlisting in any transaction.
//
#define TRANSACTION_NOTIFY_COMMIT_FINALIZE      0x40000000 


//CTL_CODE(IOCTL_DISK_BASE, 0x0085, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_GET_CLUSTER_INFO         1
//CTL_CODE(IOCTL_DISK_BASE, 0x0086, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_SET_CLUSTER_INFO         2


#define DISK_CLUSTER_FLAG_ENABLED              0x0000000000000001
#define DISK_CLUSTER_FLAG_CSV                  0x0000000000000002
#define DISK_CLUSTER_FLAG_IN_MAINTENANCE       0x0000000000000004
#define DISK_CLUSTER_FLAG_PNP_ARRIVAL_COMPLETE 0x0000000000000008

typedef struct _DISK_CLUSTER_INFO {

	//
	// Size of this structure serves
	// as the version
	//
	ULONG Version;

	//
	// Specifies whether or not this
	// disk  is clustered, csv,  etc
	//
	ULONGLONG Flags;

	//
	// Specifies  the flags that are
	// being modified
	//
	ULONGLONG FlagsMask;

	//
	// Indicates  whether  or  not a
	// layout change notification is
	// to be sent
	//
	BOOLEAN Notify;

} DISK_CLUSTER_INFO, *PDISK_CLUSTER_INFO;






typedef struct _IO_STATUS_BLOCK {
	NTSTATUS Status;

	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _ACCESS_STATE *PACCESS_STATE;
typedef struct _SECURITY_QUALITY_OF_SERVICE *PSECURITY_QUALITY_OF_SERVICE;
typedef struct _IO_SECURITY_CONTEXT {
	PSECURITY_QUALITY_OF_SERVICE SecurityQos;
	PACCESS_STATE AccessState;
	ACCESS_MASK DesiredAccess;
	ULONG FullCreateOptions;
} IO_SECURITY_CONTEXT, *PIO_SECURITY_CONTEXT;

typedef union _FLT_PARAMETERS {

	//
	//  IRP_MJ_CREATE
	struct {
		PIO_SECURITY_CONTEXT SecurityContext;

		//
		//  The low 24 bits contains CreateOptions flag values.
		//  The high 8 bits contains the CreateDisposition values.
		//

		ULONG Options;

		USHORT FileAttributes;
		USHORT ShareAccess;
		ULONG EaLength;

		PVOID EaBuffer;                 //Not in IO_STACK_LOCATION parameters list
		LARGE_INTEGER AllocationSize;   //Not in IO_STACK_LOCATION parameters list
	} Create;
	

} FLT_PARAMETERS, *PFLT_PARAMETERS;
typedef struct _FLT_IO_PARAMETER_BLOCK {


	//
	//  Fields from IRP
	//  Flags

	ULONG IrpFlags;

	//
	//  Major/minor functions from IRP
	//

	UCHAR MajorFunction;
	UCHAR MinorFunction;

	//
	//  The flags associated with operations.
	//  The IO_STACK_LOCATION.Flags field in the old model (SL_* flags)
	//

	UCHAR OperationFlags;

	//
	//  For alignment
	//

	UCHAR Reserved;


	//
	//  The FileObject that is the target for this
	//  IO operation.
	//

	PFILE_OBJECT TargetFileObject;

	//
	//  Instance that i/o is directed to
	//

	PFLT_INSTANCE TargetInstance;

	//
	//  Normalized parameters for the operation
	//

	FLT_PARAMETERS Parameters;

} FLT_IO_PARAMETER_BLOCK, *PFLT_IO_PARAMETER_BLOCK;

typedef struct _ECP_LIST *PECP_LIST;

typedef struct _FLT_CALLBACK_DATA {
	PFLT_IO_PARAMETER_BLOCK const Iopb;
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

typedef const CHAR KPROCESSOR_MODE;

typedef enum _MODE {
	KernelMode,
	UserMode,
	MaximumMode
} MODE;

typedef struct _IRP {

	ULONG Flags;

	LIST_ENTRY ThreadListEntry;

	//
	// I/O status - final status of operation.
	//

	IO_STATUS_BLOCK IoStatus;

	//
	// Requestor mode - mode of the original requestor of this operation.
	//

	KPROCESSOR_MODE RequestorMode;

	//
	// Pending returned - TRUE if pending was initially returned as the
	// status for this packet.
	//

	BOOLEAN PendingReturned;

	//
	// Stack state information.
	//

	CHAR StackCount;
	CHAR CurrentLocation;

	//
	// Cancel - packet has been canceled.
	//

	BOOLEAN Cancel;

	//
	// Cancel Irql - Irql at which the cancel spinlock was acquired.
	//

	
	UCHAR AllocationFlags;

	//
	// User parameters.
	//

	PIO_STATUS_BLOCK UserIosb;
	PKEVENT UserEvent;


	PVOID UserBuffer;


} IRP;

typedef IRP *PIRP;


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

typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,   // 2
	FileBothDirectoryInformation,   // 3
	FileBasicInformation,           // 4
	FileStandardInformation,        // 5
	FileInternalInformation,        // 6
	FileEaInformation,              // 7
	FileAccessInformation,          // 8
	FileNameInformation,            // 9
	FileRenameInformation,          // 10
	FileLinkInformation,            // 11
	FileNamesInformation,           // 12
	FileDispositionInformation,     // 13
	FilePositionInformation,        // 14
	FileFullEaInformation,          // 15
	FileModeInformation,            // 16
	FileAlignmentInformation,       // 17
	FileAllInformation,             // 18
	FileAllocationInformation,      // 19
	FileEndOfFileInformation,       // 20
	FileAlternateNameInformation,   // 21
	FileStreamInformation,          // 22
	FilePipeInformation,            // 23
	FilePipeLocalInformation,       // 24
	FilePipeRemoteInformation,      // 25
	FileMailslotQueryInformation,   // 26
	FileMailslotSetInformation,     // 27
	FileCompressionInformation,     // 28
	FileObjectIdInformation,        // 29
	FileCompletionInformation,      // 30
	FileMoveClusterInformation,     // 31
	FileQuotaInformation,           // 32
	FileReparsePointInformation,    // 33
	FileNetworkOpenInformation,     // 34
	FileAttributeTagInformation,    // 35
	FileTrackingInformation,        // 36
	FileIdBothDirectoryInformation, // 37
	FileIdFullDirectoryInformation, // 38
	FileValidDataLengthInformation, // 39
	FileShortNameInformation,       // 40
	FileIoCompletionNotificationInformation, // 41
	FileIoStatusBlockRangeInformation,       // 42
	FileIoPriorityHintInformation,           // 43
	FileSfioReserveInformation,              // 44
	FileSfioVolumeInformation,               // 45
	FileHardLinkInformation,                 // 46
	FileProcessIdsUsingFileInformation,      // 47
	FileNormalizedNameInformation,           // 48
	FileNetworkPhysicalNameInformation,      // 49
	FileIdGlobalTxDirectoryInformation,      // 50
	FileIsRemoteDeviceInformation,           // 51
	FileUnusedInformation,                   // 52
	FileNumaNodeInformation,                 // 53
	FileStandardLinkInformation,             // 54
	FileRemoteProtocolInformation,           // 55

											 //
											 //  These are special versions of these operations (defined earlier)
											 //  which can be used by kernel mode drivers only to bypass security
											 //  access checks for Rename and HardLink operations.  These operations
											 //  are only recognized by the IOManager, a file system should never
											 //  receive these.
											 //

											 FileRenameInformationBypassAccessCheck,  // 56
											 FileLinkInformationBypassAccessCheck,    // 57

																					  //
																					  // End of special information classes reserved for IOManager.
																					  //

																					  FileVolumeNameInformation,               // 58
																					  FileIdInformation,                       // 59
																					  FileIdExtdDirectoryInformation,          // 60
																					  FileReplaceCompletionInformation,        // 61
																					  FileHardLinkFullIdInformation,           // 62
																					  FileIdExtdBothDirectoryInformation,      // 63
																					  FileDispositionInformationEx,            // 64
																					  FileRenameInformationEx,                 // 65
																					  FileRenameInformationExBypassAccessCheck, // 66
																					  FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef USHORT FLT_CONTEXT_TYPE;

#define FLT_VOLUME_CONTEXT          0x0001
#define FLT_INSTANCE_CONTEXT        0x0002
#define FLT_FILE_CONTEXT            0x0004
#define FLT_STREAM_CONTEXT          0x0008
#define FLT_STREAMHANDLE_CONTEXT    0x0010
#define FLT_TRANSACTION_CONTEXT     0x0020
#define FLT_SECTION_CONTEXT         0x0040
#define FLT_CONTEXT_END             0xffff
#define FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP   0x0400
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

typedef USHORT FLT_FILE_NAME_PARSED_FLAGS;

#define FLTFL_FILE_NAME_PARSED_FINAL_COMPONENT      0x0001
#define FLTFL_FILE_NAME_PARSED_EXTENSION            0x0002
#define FLTFL_FILE_NAME_PARSED_STREAM               0x0004
#define FLTFL_FILE_NAME_PARSED_PARENT_DIR           0x0008

#define FLT_VALID_FILE_NAME_FORMATS 0x000000ff

#define FLT_FILE_NAME_NORMALIZED    0x01
#define FLT_FILE_NAME_OPENED        0x02
#define FLT_FILE_NAME_SHORT         0x03

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



typedef struct _FLT_FILE_NAME_INFORMATION {

	USHORT Size;

	//
	//  For each bit that is set in the NamesParsed flags field, the
	//  corresponding substring from Name has been appropriately
	//  parsed into one of the unicode strings below.
	//

	FLT_FILE_NAME_PARSED_FLAGS NamesParsed;

	//
	//  The name format that this FLT_FILE_NAME_INFORMATION structure
	//  represents.
	//

	FLT_FILE_NAME_OPTIONS Format;

	//
	//  For normalized and opened names, this name contains the version of
	//  name in the following format:
	//
	//    [Volume name][Full path to file][File name][Stream Name]
	//
	//    For example, the above components would map to this example name as
	//    follows:
	//
	//    \Device\HarddiskVolume1\Documents and Settings\MyUser\My Documents\Test Results.txt:stream1
	//
	//    [Volume name] = "\Device\HarddiskVolume1"
	//    [Full path to file] = "\Documents and Settings\MyUser\My Documents\"
	//    [File name] = "Test Results.txt"
	//    [Stream name] = ":stream1"
	//
	//  For short names, only the short name for the final name component is
	//  returned in the Name unicode string.  Therefore, if you requested
	//  the short name of the file object representing an open on the file:
	//
	//    \Device\HarddiskVolume1\Documents and Settings\MyUser\My Documents\Test Results.txt
	//
	//  The name returned in Name will be at most 8 characters followed by a '.'
	//  then at most 3 more characters, like:
	//
	//    testre~1.txt
	//

	UNICODE_STRING Name;

	//
	//  The Volume is only filled in for name requested in normalized and opened
	//  formats.
	//

	UNICODE_STRING Volume;

	//
	//  The share component of the file name requested.  This will only be
	//  set for normalized and opened name formats on files that opened across
	//  redirectors.  For local files, this string will always be 0 length.
	//

	UNICODE_STRING Share;

	//
	//  To exemplify what each of the following substrings refer to, let's
	//  look again at the first example string from above:
	//
	//    \Device\HarddiskVolume1\Documents and Settings\MyUser\My Documents\Test Results.txt:stream1
	//
	//  Extension = "txt"
	//  Stream = ":stream1"
	//  FinalComponent = "Test Results.txt:stream1"
	//  ParentDir = "\Documents and Settings\MyUser\My Documents\"
	//

	//
	//  This can be parsed from a normalized, opened, or short name.
	//

	UNICODE_STRING Extension;

	//
	//  The following parse formats are only available for normalized and
	//  opened name formats, but not short names.
	//

	UNICODE_STRING Stream;
	UNICODE_STRING FinalComponent;
	UNICODE_STRING ParentDir;

} FLT_FILE_NAME_INFORMATION, *PFLT_FILE_NAME_INFORMATION;


typedef struct _FILE_BASIC_INFORMATION {
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

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
FORCEINLINE PVOID
InterlockedCompareExchangePointer(

	PVOID volatile *Destination,
	_In_opt_ PVOID Exchange,
	_In_opt_ PVOID Comperand
)
{
	PVOID oldValue = *Destination;
	if (*Destination == Comperand)
	{
		*Destination = Exchange;
	}
	return oldValue;
}
FORCEINLINE PVOID
InterlockedExchangePointer(
	PVOID volatile *Target,
	_In_opt_ PVOID Value
)
{
	PVOID oldValue = *Target;
	*Target = Value;
	return oldValue;
}

typedef
NTSTATUS
DRIVER_INITIALIZE(
	_In_ struct _DRIVER_OBJECT *DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

FORCEINLINE
PVOID ExAllocatePoolWithTag(_In_ POOL_TYPE PoolType, _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag)
{
	return 0;
}
FORCEINLINE
VOID ExFreePoolWithTag(PVOID P, _In_ ULONG Tag)
{

}
FORCEINLINE VOID KeEnterCriticalRegion()
{}
FORCEINLINE VOID KeLeaveCriticalRegion()
{}
	
FORCEINLINE BOOLEAN ExAcquireResourceExclusiveLite(PERESOURCE Resource, BOOLEAN Wait)
{
	return TRUE;
}

FORCEINLINE VOID ExReleaseResourceLite(_Inout_ PERESOURCE Resource)
{}


FORCEINLINE VOID FltCancelFileOpen(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject)
{}

FORCEINLINE NTSTATUS FltAllocateContext(
	_In_ PFLT_FILTER Filter,
	_In_ FLT_CONTEXT_TYPE ContextType,
	_In_ SIZE_T ContextSize,
	_In_ POOL_TYPE PoolType,
	_Outptr_result_bytebuffer_(ContextSize) PFLT_CONTEXT *ReturnedContext
)
{
	return 0;
}


FORCEINLINE ULONG DbgPrint(PCSTR Format, ...)
{
	return 0;
}
#define RtlZeroMemory(Destination,Length) memset((Destination),0,(Length))

FORCEINLINE NTSTATUS
FltBuildDefaultSecurityDescriptor(
	_Outptr_ PSECURITY_DESCRIPTOR *SecurityDescriptor,
	_In_ ACCESS_MASK DesiredAccess
)
{
	return 0;
}

FORCEINLINE NTSTATUS
FltSetInstanceContext(
	_In_ PFLT_INSTANCE Instance,
	_In_ FLT_SET_CONTEXT_OPERATION Operation,
	_In_ PFLT_CONTEXT NewContext,
	_Outptr_opt_result_maybenull_ PFLT_CONTEXT *OldContext
)
{
	return 0;
}


FORCEINLINE NTSTATUS
FltSetFileContext(
	_In_ PFLT_INSTANCE Instance,
	_In_ PFILE_OBJECT FileObject,
	_In_ FLT_SET_CONTEXT_OPERATION Operation,
	_In_ PFLT_CONTEXT NewContext,
	_Outptr_opt_result_maybenull_ PFLT_CONTEXT *OldContext
)
{
	return 0;
}


FORCEINLINE NTSTATUS
FltRegisterForDataScan(
	_In_ PFLT_INSTANCE Instance
)
{
	return 0;
}
FORCEINLINE
NTSTATUS
FltGetInstanceContext(
	_In_ PFLT_INSTANCE Instance,
	_Outptr_ PFLT_CONTEXT *Context
)
{
	return 0;
}
FORCEINLINE NTSTATUS
FltDeleteInstanceContext(
	_In_ PFLT_INSTANCE Instance,
	_Outptr_opt_result_maybenull_ PFLT_CONTEXT *OldContext
)
{
	return 0;
}


FORCEINLINE NTSTATUS
FltRegisterFilter(
	_In_ PDRIVER_OBJECT Driver,
	_In_ CONST FLT_REGISTRATION *Registration,
	_Outptr_ PFLT_FILTER *RetFilter
)
{
	return 0;
}


FORCEINLINE VOID
FltUnregisterFilter(
	_In_ PFLT_FILTER Filter
)
{
}

FORCEINLINE NTSTATUS
FltStartFiltering(
	_In_ PFLT_FILTER Filter
)
{
	return 0;
}


FORCEINLINE VOID
FltFreeSecurityDescriptor(
	_In_ PSECURITY_DESCRIPTOR SecurityDescriptor
)
{
}

FORCEINLINE NTSTATUS
FltCancellableWaitForSingleObject(
	_In_ PVOID Object,
	_In_opt_ PLARGE_INTEGER Timeout,
	_In_opt_ PFLT_CALLBACK_DATA CallbackData
)
{
	return 0;
}


FORCEINLINE NTSTATUS
FltGetEcpListFromCallbackData(
	_In_ PFLT_FILTER Filter,
	_In_ PFLT_CALLBACK_DATA CallbackData,
	_Outptr_result_maybenull_ PECP_LIST *EcpList
)
{
	return 0;
}

typedef ULONG NOTIFICATION_MASK;
FORCEINLINE NTSTATUS
FltEnlistInTransaction(
	_In_ PFLT_INSTANCE Instance,
	_In_ PKTRANSACTION Transaction,
	_In_ PFLT_CONTEXT TransactionContext,
	_In_ NOTIFICATION_MASK NotificationMask
)
{
	return 0;
}


FORCEINLINE NTSTATUS
FltSetStreamHandleContext(
	_In_ PFLT_INSTANCE Instance,
	_In_ PFILE_OBJECT FileObject,
	_In_ FLT_SET_CONTEXT_OPERATION Operation,
	_In_ PFLT_CONTEXT NewContext,
	_Outptr_opt_result_maybenull_ PFLT_CONTEXT *OldContext
)
{
	return 0;
}

FORCEINLINE BOOLEAN
FltSupportsStreamHandleContexts(
	_In_ PFILE_OBJECT FileObject
)
{
	return TRUE;
}

FORCEINLINE NTSTATUS
FltSetStreamContext(
	_In_ PFLT_INSTANCE Instance,
	_In_ PFILE_OBJECT FileObject,
	_In_ FLT_SET_CONTEXT_OPERATION Operation,
	_In_ PFLT_CONTEXT NewContext,
	_Outptr_opt_result_maybenull_ PFLT_CONTEXT *OldContext
)
{
	return 0;
}
FORCEINLINE NTSTATUS
FltGetDiskDeviceObject(
	_In_ PFLT_VOLUME Volume,
	_Outptr_ PDEVICE_OBJECT *DiskDeviceObject
)
{
	return 0;
}

FORCEINLINE NTSTATUS
FltIsDirectory(
	_In_ PFILE_OBJECT FileObject,
	_In_ PFLT_INSTANCE Instance,
	_Out_ PBOOLEAN IsDirectory
)
{
	return 0;
}

FORCEINLINE NTSTATUS
FltGetStreamContext(
	_In_ PFLT_INSTANCE Instance,
	_In_ PFILE_OBJECT FileObject,
	_Outptr_ PFLT_CONTEXT *Context
)
{
	return 0;
}

FORCEINLINE NTSTATUS
FltGetFileNameInformation(
	_In_ PFLT_CALLBACK_DATA CallbackData,
	_In_ FLT_FILE_NAME_OPTIONS NameOptions,
	_Outptr_ PFLT_FILE_NAME_INFORMATION *FileNameInformation
)
{
	return 0;
}

FORCEINLINE NTSTATUS
FltGetFileNameInformationUnsafe(
	_In_ PFILE_OBJECT FileObject,
	_In_opt_ PFLT_INSTANCE Instance,
	_In_ FLT_FILE_NAME_OPTIONS NameOptions,
	_Outptr_ PFLT_FILE_NAME_INFORMATION *FileNameInformation
)
{
	return 0;
}
FORCEINLINE
VOID
FltReleaseFileNameInformation(
	_In_ PFLT_FILE_NAME_INFORMATION FileNameInformation
)
{
}

FORCEINLINE VOID
FltReferenceFileNameInformation(
	_In_ PFLT_FILE_NAME_INFORMATION FileNameInformation
)
{}

FORCEINLINE NTSTATUS
FltParseFileName(
	_In_ PCUNICODE_STRING FileName,
	_Inout_opt_ PUNICODE_STRING Extension,
	_Inout_opt_ PUNICODE_STRING Stream,
	_Inout_opt_ PUNICODE_STRING FinalComponent
)
{
	return 0;
}

NTSTATUS
FltQueryInformationFile(
	_In_ PFLT_INSTANCE Instance,
	_In_ PFILE_OBJECT FileObject,
	_Out_writes_bytes_to_(Length, *LengthReturned) PVOID FileInformation,
	_In_ ULONG Length,
	_In_ FILE_INFORMATION_CLASS FileInformationClass,
	_Out_opt_ PULONG LengthReturned
)
{
	return 0;
}

GUID GUID_ECP_CSV_DOWN_LEVEL_OPEN = { 0 };
GUID GUID_ECP_PREFETCH_OPEN = { 0 };

FORCEINLINE NTSTATUS
FltParseFileNameInformation(
	_Inout_ PFLT_FILE_NAME_INFORMATION FileNameInformation
)
{
	return 0;
}
FORCEINLINE NTSTATUS
FltFindExtraCreateParameter(
	_In_ PFLT_FILTER Filter,
	_In_ PECP_LIST EcpList,
	_In_ LPCGUID EcpType,
	_Outptr_opt_result_buffer_(*EcpContextSize) PVOID *EcpContext,
	_Out_opt_ ULONG *EcpContextSize
)
{
	return 0;
}
FORCEINLINE BOOLEAN
FltIsEcpFromUserMode(
	_In_ PFLT_FILTER Filter,
	_In_ PVOID EcpContext
)
{
	return FALSE;
}
FORCEINLINE NTSTATUS
FltGetTransactionContext(
	_In_ PFLT_INSTANCE Instance,
	_In_ PKTRANSACTION Transaction,
	_Outptr_ PFLT_CONTEXT *Context
)
{
	return 0;
}





FORCEINLINE VOID
FltReferenceContext(
	_In_ PFLT_CONTEXT Context
) {}

FORCEINLINE VOID
FltReleaseContext(
	_In_ PFLT_CONTEXT Context
)
{}


FORCEINLINE NTSTATUS
FltSetTransactionContext(
	_In_ PFLT_INSTANCE Instance,
	_In_ PKTRANSACTION Transaction,
	_In_ FLT_SET_CONTEXT_OPERATION Operation,
	_In_ PFLT_CONTEXT NewContext,
	_Outptr_opt_ PFLT_CONTEXT *OldContext
)
{
	return 0;
}

typedef enum _TRANSACTION_INFORMATION_CLASS {
	TransactionBasicInformation,
	TransactionPropertiesInformation,
	TransactionEnlistmentInformation,
	TransactionSuperiorEnlistmentInformation
} TRANSACTION_INFORMATION_CLASS;

FORCEINLINE void FsRtlEnterFileSystem()
{

}
FORCEINLINE void FsRtlExitFileSystem()
{

}
FORCEINLINE VOID IoGetStackLimits(
	_Out_ PULONG_PTR LowLimit,
	_Out_ PULONG_PTR HighLimit
)
{
	*LowLimit = 0x1000;
	*HighLimit = 0x10000;
}

POBJECT_TYPE *TmTransactionObjectType = 0;

FORCEINLINE NTSTATUS
ZwQueryInformationTransaction(
	_In_ HANDLE TransactionHandle,
	_In_ TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
	_Out_writes_bytes_(TransactionInformationLength) PVOID TransactionInformation,
	_In_ ULONG TransactionInformationLength,
	_Out_opt_ PULONG ReturnLength
)
{
	return 0;
}

typedef enum _TRANSACTION_OUTCOME {
	TransactionOutcomeUndetermined = 1,
	TransactionOutcomeCommitted,
	TransactionOutcomeAborted,
} TRANSACTION_OUTCOME;


typedef enum _KWAIT_REASON {
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrSpare0,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	WrKeyedEvent,
	WrTerminated,
	WrProcessInSwap,
	WrCpuRateControl,
	WrCalloutStack,
	WrKernel,
	WrResource,
	WrPushLock,
	WrMutex,
	WrQuantumEnd,
	WrDispatchInt,
	WrPreempted,
	WrYieldExecution,
	WrFastMutex,
	WrGuardedMutex,
	WrRundown,
	WrAlertByThreadId,
	WrDeferredPreempt,
	MaximumWaitReason
} KWAIT_REASON;


FORCEINLINE NTSTATUS
KeWaitForSingleObject(
	_In_ _Points_to_data_ PVOID Object,
	_In_ _Strict_type_match_ KWAIT_REASON WaitReason,
	_In_ KPROCESSOR_MODE WaitMode,
	_In_ BOOLEAN Alertable,
	_In_opt_ PLARGE_INTEGER Timeout
)
{
	return 0;
}


FORCEINLINE NTSTATUS
ObOpenObjectByPointer(
	_In_ PVOID Object,
	_In_ ULONG HandleAttributes,
	_In_opt_ PACCESS_STATE PassedAccessState,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_TYPE ObjectType,
	_In_ KPROCESSOR_MODE AccessMode,
	_Out_ PHANDLE Handle
)
{
	return 0;
}

FORCEINLINE NTSTATUS ObDereferenceObject(
	_In_ PVOID Object
)
{
	return 0;
}

FORCEINLINE NTSTATUS
ObReferenceObject(
	_In_ PVOID Object
)
{
	return 0;
}

FORCEINLINE NTSTATUS
ZwClose(
	_In_ HANDLE Handle
)
{
	return 0;
}
FORCEINLINE PDEVICE_OBJECT
IoGetAttachedDeviceReference(
	_In_ PDEVICE_OBJECT DeviceObject
)
{
	return 0;
}
FORCEINLINE VOID
KeInitializeEvent(
	_Out_ PRKEVENT Event,
	_In_ EVENT_TYPE Type,
	_In_ BOOLEAN State
)
{}

FORCEINLINE PIRP
IoBuildDeviceIoControlRequest(
	_In_  ULONG IoControlCode,
	_In_  PDEVICE_OBJECT DeviceObject,
	_In_opt_  PVOID InputBuffer,
	_In_  ULONG InputBufferLength,
	_Out_opt_ PVOID OutputBuffer,
	_In_ ULONG OutputBufferLength,
	_In_ BOOLEAN InternalDeviceIoControl,
	_In_opt_ PKEVENT Event,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock
)
{
	return 0;
}
FORCEINLINE
NTSTATUS
IoCallDriver(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	return 0;
}

FORCEINLINE NTSTATUS
ExInitializeResourceLite(
	_Out_ PERESOURCE Resource
)
{
	return 0;
}

FORCEINLINE NTSTATUS
ExDeleteResourceLite(
	_Inout_ PERESOURCE Resource
)
{
	return 0;
}


FORCEINLINE LONG
KeSetEvent(
	_Inout_ PRKEVENT Event,
	_In_ KPRIORITY Increment,
	_In_ _Literal_ BOOLEAN Wait
)
{
	return 0;
}


FORCEINLINE
VOID
InitializeListHead(
	_Out_ PLIST_ENTRY ListHead
)
{}

FORCEINLINE
BOOLEAN
RemoveEntryList(
	_In_ PLIST_ENTRY Entry
)
{
	return TRUE;
}
FORCEINLINE
VOID
InsertTailList(
	_Inout_ PLIST_ENTRY ListHead,
	_Out_ PLIST_ENTRY Entry
)
{

}

