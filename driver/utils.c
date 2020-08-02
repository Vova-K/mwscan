//utils.c
#include "utils.h"

NTSTATUS UtilGetFileId(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PMW_UNIQUE_FILE_ID FileId)
{
    NTSTATUS status = STATUS_SUCCESS;
    FLT_FILESYSTEM_TYPE type;
    status = FltGetFileSystemType(Instance, &type);

    if (NT_SUCCESS(status))
    {
        if (type == FLT_FSTYPE_REFS)
        {
            FILE_ID_INFORMATION fileIdInformation;
            status = FltQueryInformationFile(Instance, FileObject, &fileIdInformation, sizeof(FILE_ID_INFORMATION), FileIdInformation, NULL);
            if (NT_SUCCESS(status))
            {
                RtlCopyMemory(&(FileId->FileId128), &(fileIdInformation.FileId), sizeof(FileId->FileId128));
            }
        }
        else
        {
            FILE_INTERNAL_INFORMATION fileInternalInformation;
            status = FltQueryInformationFile(Instance, FileObject, &fileInternalInformation, sizeof(FILE_INTERNAL_INFORMATION), FileInternalInformation, NULL);
            if (NT_SUCCESS(status))
            {
                FileId->FileId64.Value = fileInternalInformation.IndexNumber.QuadPart;
                FileId->FileId64.UpperZeroes = 0ll;
            }
        }
    }
    return status;
}

NTSTATUS UtilGetFileSize(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject, _Out_ PLONGLONG Size)
{
    NTSTATUS status = STATUS_SUCCESS;
    FILE_STANDARD_INFORMATION standardInfo;
    status = FltQueryInformationFile(Instance, FileObject, &standardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, NULL);
    if (NT_SUCCESS(status))
    {
        *Size = standardInfo.EndOfFile.QuadPart;
    }
    return status;
}
