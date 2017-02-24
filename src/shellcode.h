#ifndef SHELLCODE_H
#define SHELLCODE_H

#include <windows.h>

#define SHELLCODE_FILE 		"shellcode.bin"
#define SHELLCODE_SECTION 	"shell"


typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _PEB_LDR_DATA
{
	UINT8 _PADDING_[12];
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
#ifdef _WIN64
	UINT8 _PADDING_[24];
#else
	UINT8 _PADDING_[12];
#endif
	PEB_LDR_DATA* Ldr;
} PEB, *PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	VOID* DllBase;
	PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

HMODULE GetKernel32(void);
DWORD CalcHashW(wchar_t * str);
void * CallAPI(DWORD dwHash, DWORD nArgs, ...);
__declspec(noinline) void Entry(void);

#endif
