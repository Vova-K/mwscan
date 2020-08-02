//scanner.h
#pragma once

typedef enum _FILE_SCAN_RESULT
{
    ScanResultUnset,
    ScanResultDetected,
    ScanResultClean
} FILE_SCAN_RESULT;


//if set to '1' the create/open IO on the infected file will be blocked
#define BLOCK_INFECTED 1

NTSTATUS PerformScan(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ UCHAR IOMajorFunctionAtScan, _In_ BOOLEAN inTransaction, _In_ PMW_STREAM_CONTEXT StreamContext);
