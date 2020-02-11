// vmmwindef.h : windows-related defines not in the standard header files.
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMWINDEF_H__
#define __VMMWINDEF_H__
#include <windows.h>

#define O32_FILE_OBJECT_SectionObjectPointer            0x014
#define O64_FILE_OBJECT_SectionObjectPointer            0x028
#define O32_FILE_OBJECT_PrivateCacheMap                 0x018
#define O64_FILE_OBJECT_PrivateCacheMap                 0x030
#define O32_FILE_OBJECT_FileName                        0x030
#define O64_FILE_OBJECT_FileName                        0x058

#define O32_SECTION_OBJECT_POINTERS_DataSectionObject   0x000
#define O64_SECTION_OBJECT_POINTERS_DataSectionObject   0x000
#define O32_SECTION_OBJECT_POINTERS_SharedCacheMap      0x004
#define O64_SECTION_OBJECT_POINTERS_SharedCacheMap      0x008
#define O32_SECTION_OBJECT_POINTERS_ImageSectionObject  0x008
#define O64_SECTION_OBJECT_POINTERS_ImageSectionObject  0x010

#define O32_SEGMENT_SizeOfSegment                       0x010
#define O64_SEGMENT_SizeOfSegment                       0x018

#define O_SHARED_CACHE_MAP_FileSize                     0x008
#define O_CONTROL_AREA_Segment                          0x000

typedef struct _UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    DWORD  Buffer;
} UNICODE_STRING32, *PUNICODE_STRING32;

typedef struct _UNICODE_STRING64 {
    USHORT Length;
    USHORT MaximumLength;
    DWORD  Filler;
    QWORD  Buffer;
} UNICODE_STRING64, *PUNICODE_STRING64;

#endif /* __VMMWINDEF_H__ */
