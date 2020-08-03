#include "../driver/main.c"
#include <cstdio>
#include <cassert>

//TODO: move these to mocking object
NTSTATUS UtilGetFileId(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject, _Out_ PMW_UNIQUE_FILE_ID FileId)
{
	return STATUS_SUCCESS;
}
NTSTATUS UtilGetFileSize(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject, _Out_ PLONGLONG Size)
{
	return STATUS_SUCCESS;
}

NTSTATUS PerformScan(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ UCHAR IOMajorFunctionAtScan, _In_ BOOLEAN inTransaction, _In_ PMW_STREAM_CONTEXT StreamContext)
{
	return STATUS_SUCCESS;
}
int main()
{
	FLT_RELATED_OBJECTS FltObjects;
	FltObjects.Transaction = NULL;
	MW_STREAM_CONTEXT StreamContext;
	StreamContext.TransactionContext = NULL;
	NTSTATUS status = ProcessTransactions(&FltObjects, &StreamContext);
	assert(status == STATUS_SUCCESS);
	printf("Done!");
    return 0;
}

