//context.c
#include "context.h"
#include "utils.h"

//locals
NTSTATUS CloseSectionForDataScan(_Inout_ PMW_FILE_SECTION_CONTEXT SectionContext);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CreateFileSectionContext)
#pragma alloc_text(PAGE, FinalizeSectionContext)
#endif
/*++
Creates new file section context

Return Value:
The status of this operation.
--*/
NTSTATUS CreateFileSectionContext(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject, _Outptr_ PMW_FILE_SECTION_CONTEXT *SectionContext)
{
    NTSTATUS status;
    LONGLONG fileSize;
    PMW_FILE_SECTION_CONTEXT sectionContext = NULL;

    PAGED_CODE();

    status = FltAllocateContext(Globals.Filter,
                                FLT_SECTION_CONTEXT,
                                sizeof(MW_FILE_SECTION_CONTEXT),
                                PagedPool,
                                &sectionContext);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Failed to allocate section context: 0x%x", status);
        return status;
    }

    RtlZeroMemory(sectionContext, sizeof(MW_FILE_SECTION_CONTEXT));

    status = UtilGetFileSize(Instance, FileObject, &fileSize);

    if (!NT_SUCCESS(status))
    {
        DbgPrint(" Failed to get file size: 0x%x", status);
    }
    else
    {
        sectionContext->FileSize = fileSize;
    }
    *SectionContext = sectionContext;
    return STATUS_SUCCESS;
}

NTSTATUS FinalizeSectionContext(_Inout_ PMW_FILE_SECTION_CONTEXT SectionContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    PAGED_CODE();
    status = CloseSectionForDataScan(SectionContext);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("CloseSectionForDataScan failed: %x", status);
    }
    FltReleaseContext(SectionContext);
    return status;
}

NTSTATUS CloseSectionForDataScan(_Inout_ PMW_FILE_SECTION_CONTEXT SectionContext)
{
    ObDereferenceObject(SectionContext->SectionObject);
    SectionContext->SectionHandle = NULL;
    SectionContext->SectionObject = NULL;
    return FltCloseSectionForDataScan((PFLT_CONTEXT)SectionContext);
}
