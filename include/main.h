#pragma once

#include <fltKernel.h>

#pragma prefast(disable \
                : __WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define DRIVER_NAME  "mwscan"
//
//Memory allocation tags
//
#define MW_RESOURCE_TAG 'cRwM'
#define MW_KEVENT_TAG   'eKwM'
