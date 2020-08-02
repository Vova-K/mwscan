//context.h
#pragma once
#include <fltKernel.h>
#include <ntdddisk.h>

typedef enum _MW_INFECTED_STATE
{
	InfectedStateUnknown,
	InfectedStateInfected,
	InfectedStateClean,
	InfectedStateModified
} MW_INFECTED_STATE;

//
//Memory allocation tags
//
#define STREAMHANDLE_CONTEXT_TAG 'hSwM'
#define STREAM_CONTEXT_TAG 'cSwM'
#define TRANSACTION_CONTEXT_TAG 'cTwM'
#define SECTION_CONTEXT_TAG 'eSwM'
#define INSTANCE_CONTEXT_TAG 'cIwM'

//
//  Defines the transaction context structure
//
#define TRANSACTION_FLAGS_ENLISTED 0x01
#define TRANSACTION_FLAGS_LISTDRAINED 0x02

typedef struct _MW_TRANSACTION
{
	PKTRANSACTION Transaction;
	LIST_ENTRY ScListHead;
	PERESOURCE Resource;
	ULONG Flags;
} MW_TRANSACTION, *PMW_TRANSACTION;

//  Stream/Stream Handle flags
#define MW_PREFETCH 0x00000001

typedef struct _MW_STREAMHANDLE
{
	ULONG Flags;
} MW_STREAMHANDLE, *PMW_STREAMHANDLE;

typedef union _MW_UNIQUE_FILE_ID {
	struct
	{
		ULONGLONG Value;
		ULONGLONG UpperZeroes;
	} FileId64;

	FILE_ID_128 FileId128;

} MW_UNIQUE_FILE_ID, *PMW_UNIQUE_FILE_ID;

#define SET_INVALID_FILE_ID(_fileid_)      \
	(_fileid_).FileId64.UpperZeroes = 0ll; \
	(_fileid_).FileId64.Value = (ULONGLONG)FILE_INVALID_FILE_ID;

typedef struct _MW_STREAM_CONTEXT
{
	MW_UNIQUE_FILE_ID FileId;
	PMW_TRANSACTION TransactionContext;
	LIST_ENTRY ListInTransaction;
	PKEVENT ScanCompleteEvent;
	volatile LONG FinalState; //MW_INFECTED_STATE!
	volatile LONG TxState;	  //MW_INFECTED_STATE!

} MW_STREAM_CONTEXT, *PMW_STREAM_CONTEXT;

typedef struct _MW_FILE_SECTION_CONTEXT
{
	HANDLE SectionHandle;
	PVOID SectionObject;
	BOOLEAN ScanAborted;
	LONGLONG FileSize;
	BOOLEAN CancelableOnConflictingIo;
} MW_FILE_SECTION_CONTEXT, *PMW_FILE_SECTION_CONTEXT;

typedef struct _MW_INSTANCE_CONTEXT
{
	PFLT_VOLUME Volume;
	PFLT_INSTANCE Instance;
	FLT_FILESYSTEM_TYPE VolumeFSType;
} MW_INSTANCE_CONTEXT, *PMW_INSTANCE_CONTEXT;

//
//Context helper APIs
//
FORCEINLINE BOOLEAN IsFileInfected(_In_ PMW_STREAM_CONTEXT streamContext)
{
	return (streamContext->FinalState == InfectedStateInfected);
}

FORCEINLINE BOOLEAN IsFileModified(_In_ PMW_STREAM_CONTEXT streamContext)
{
	return (streamContext->FinalState == InfectedStateModified);
}

FORCEINLINE BOOLEAN IsFileTransModified(_In_ PMW_STREAM_CONTEXT streamContext)
{
	return (streamContext->TxState == InfectedStateModified);
}

FORCEINLINE BOOLEAN IsFileNeedScan(_In_ PMW_STREAM_CONTEXT streamContext)
{
	return ((streamContext->TransactionContext == NULL) && IsFileModified(streamContext)) ||
		   ((streamContext->TransactionContext != NULL) && IsFileTransModified(streamContext));
}

FORCEINLINE VOID SetContextFlagUnknown(_Inout_ _Interlocked_operand_ LONG volatile *Flag)
{
	InterlockedExchange(Flag, InfectedStateUnknown);
}

FORCEINLINE VOID SetContextFlagModified(_Inout_ _Interlocked_operand_ LONG volatile *Flag)
{
	InterlockedExchange(Flag, InfectedStateModified);
}

FORCEINLINE VOID SetContextFlagInfected(_Inout_ _Interlocked_operand_ LONG volatile *Flag)
{
	InterlockedExchange(Flag, InfectedStateInfected);
}

FORCEINLINE VOID SetContextFlagClean(_Inout_ _Interlocked_operand_ LONG volatile *Flag)
{
	InterlockedExchange(Flag, InfectedStateClean);
}

FORCEINLINE VOID SetFileUnknownEx(_In_ BOOLEAN inTransaction, _Inout_ PMW_STREAM_CONTEXT streamContext)
{
	if (inTransaction)
	{
		SetContextFlagUnknown(&(streamContext->TxState));
	}
	else
	{
		SetContextFlagUnknown(&(streamContext->FinalState));
	}
}
/*
FORCEINLINE VOID SetFileModifiedEx(_In_ BOOLEAN inTransaction, _Inout_ PMW_STREAM_CONTEXT streamContext)
{
	if (inTransaction)
	{
		SetContextFlagModified(&(streamContext->TxState));
	}
	else
	{
		SetContextFlagModified(&(streamContext->FinalState));
	}
}
*/

FORCEINLINE VOID SetFileInfectedEx(_In_ BOOLEAN inTransaction, _Inout_ PMW_STREAM_CONTEXT streamContext)
{
	if (inTransaction)
	{
		SetContextFlagInfected(&(streamContext->TxState));
	}
	else
	{
		SetContextFlagInfected(&(streamContext->FinalState));
	}
}
FORCEINLINE VOID SetFileCleanEx(_In_ BOOLEAN inTransaction, _Inout_ PMW_STREAM_CONTEXT streamContext)
{
	if (inTransaction)
	{
		SetContextFlagClean(&(streamContext->TxState));
	}
	else
	{
		SetContextFlagClean(&(streamContext->FinalState));
	}
}

NTSTATUS CreateFileSectionContext(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject, _Outptr_ PMW_FILE_SECTION_CONTEXT *SectionContext);
NTSTATUS FinalizeSectionContext(_Inout_ PMW_FILE_SECTION_CONTEXT SectionContext);