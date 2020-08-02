//scanner.h
#pragma once

typedef enum _FILE_SCAN_RESULT
{
    ScanResultUnset,
    ScanResultDetected,
    ScanResultClean
} FILE_SCAN_RESULT;

#define SIGNATURE_TO_FIND "Microsoft.Windows.Magnifier"

NTSTATUS PerformScan(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ UCHAR IOMajorFunctionAtScan, _In_ BOOLEAN inTransaction, _In_ PMW_STREAM_CONTEXT StreamContext);
