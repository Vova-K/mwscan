//utils.h
#pragma once
#include <fltKernel.h>
#include <ntdddisk.h>
#include "context.h"

typedef struct _MW_GLOBAL_DATA
{
    PFLT_FILTER Filter;
    volatile LONG DriverIsUnloading;
} MW_GLOBAL_DATA;

extern MW_GLOBAL_DATA Globals;

#define LIST_FOR_EACH_SAFE(curr, n, head)                       \
    for (curr = (head)->Flink, n = curr->Flink; curr != (head); \
         curr = n, n = curr->Flink)

NTSTATUS UtilGetFileId(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject, _Out_ PMW_UNIQUE_FILE_ID FileId);
NTSTATUS UtilGetFileSize(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject, _Out_ PLONGLONG Size);
