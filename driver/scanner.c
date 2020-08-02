#include "utils.h"
#include "context.h"
#include "scanner.h"

CHAR MW_SIGNATURE[] =
#include "signature.txt"
    ;

//Local utils

/*++
	Scan the memory starting at StartingAddress.

Arguments
	StartingAddress - The starting memory address to be scanned.
	Size - The size of the memory to be scanned.
	OperationCanceled - In the scan loop, it is supposed to poll this flag, to see if the operation has been canceled.

Return Value
	The scan result
--*/

FILE_SCAN_RESULT DoScanMemoryStream(_In_reads_bytes_(Size) PVOID StartingAddress, _In_ SIZE_T Size, _In_ PBOOLEAN OperationCanceled)
{
    //CHAR signature[] = SIGNATURE_TO_FIND;
    UCHAR targetString[sizeof(MW_SIGNATURE)] = {0};
    SIZE_T searchStringLength = sizeof(MW_SIGNATURE) - 1;
    //ULONG ind;
    PUCHAR p;
    PUCHAR start = StartingAddress;
    PUCHAR end = start + Size - searchStringLength;

    RtlCopyMemory((PVOID)targetString, MW_SIGNATURE, sizeof(MW_SIGNATURE));

    DbgPrint("Scan memory: %p, %p, %llu ", start, end, Size);

    for (p = start; p <= end; p++)
    {
        // if not canceled, continue to search for pattern
        if ((*OperationCanceled))
        {
            return ScanResultUnset;
        }

        if (RtlEqualMemory(p, targetString, searchStringLength))
        {
            return ScanResultDetected;
        }
    }
    *OperationCanceled = FALSE; // Reset the cancel flag, after breaks out the loop.
    return ScanResultClean;
}
/*++
	Map the section object and scan the mapped memory.

Arguments
	SectionContext - Section context containing section object and handle.
	Infected - Return TRUE if the file is infected.

Return Value
	The status of this operation.
--*/
NTSTATUS DoMapSectionAndScan(_Inout_ PMW_FILE_SECTION_CONTEXT SectionContext, _Out_ FILE_SCAN_RESULT *ScanResult)
{
    NTSTATUS status;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES objAttribs;
    HANDLE processHandle = NULL;

    clientId.UniqueThread = PsGetCurrentThreadId();
    clientId.UniqueProcess = PsGetCurrentProcessId();

    InitializeObjectAttributes(&objAttribs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objAttribs, &clientId);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("ZwOpenProcess failed: 0x%x", status);
        return status;
    }
    do
    {
        PVOID scanAddress = NULL;
        SIZE_T scanSize = 0;
        FILE_SCAN_RESULT scanResult;

        status = ZwMapViewOfSection(SectionContext->SectionHandle, processHandle, &scanAddress, 0, 0, NULL, &scanSize, ViewUnmap, 0, PAGE_READONLY);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("ZwMapViewOfSection failed: 0x%x", status);
            break;
        }
        //  The size here may have truncation.
        scanResult = DoScanMemoryStream(scanAddress, (SIZE_T)min((LONGLONG)scanSize, SectionContext->FileSize), &SectionContext->ScanAborted);
        *ScanResult = scanResult;
        ZwUnmapViewOfSection(processHandle, scanAddress);
    } while (0);
    ZwClose(processHandle);
    return status;
}

/*++
	This function performs file scan.

Arguments

	FltObjects - related objects for the IO operation.
	IOMajorFunctionAtScan - The major function of the IRP that issues this scan.
	IsInTxWriter - If this file is enlisted in a transacted writer.
	StreamContext - The stream context of this data stream.

Return Value
	Returns the status of this operation.
--*/

NTSTATUS PerformScan(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ UCHAR IOMajorFunctionAtScan, _In_ BOOLEAN inTransaction, _In_ PMW_STREAM_CONTEXT StreamContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES objAttribs;
    PMW_FILE_SECTION_CONTEXT sectionContext;
    FILE_SCAN_RESULT scanResult = ScanResultUnset;

    status = CreateFileSectionContext(FltObjects->Instance, FltObjects->FileObject, &sectionContext);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("CreateSectionContext failed: 0x%x", status);
        return status;
    }
    sectionContext->CancelableOnConflictingIo = (IOMajorFunctionAtScan == IRP_MJ_CLEANUP);
    InitializeObjectAttributes(&objAttribs, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = FltCreateSectionForDataScan(FltObjects->Instance,
                                         FltObjects->FileObject,
                                         sectionContext,
                                         SECTION_MAP_READ,
                                         &objAttribs,
                                         NULL,
                                         PAGE_READONLY,
                                         SEC_COMMIT,
                                         0,
                                         &sectionContext->SectionHandle,
                                         &sectionContext->SectionObject,
                                         NULL);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("FltCreateSectionForDataScan failed: 0x%x", status);
        return status;
    }

    status = DoMapSectionAndScan(sectionContext, &scanResult);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("MapSectionAndScan failed: 0x%x", status);
    }
    switch (scanResult)
    {
    case ScanResultClean:
        SetFileCleanEx(inTransaction, StreamContext);
        break;
    case ScanResultDetected:
        SetFileInfectedEx(inTransaction, StreamContext);
        break;
    default:
        SetFileUnknownEx(inTransaction, StreamContext);
        break;
    }
    status = FinalizeSectionContext(sectionContext);
    return status;
}
