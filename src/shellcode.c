#include "shellcode.h"

#pragma code_seg("shell")

#define dwBeep 0xfa2c2f56

__declspec(noinline) void Entry(void)
{
	CallAPI(dwBeep, 2, 700, 1400);
}

DWORD CalcHashW(wchar_t * str)
{
	DWORD hash = 0x01b63a;

	for (; *str != 0; ++str)
	{
		hash = ((hash << 5) + hash) + (*str);
	}
	return hash;
}

DWORD CalcHashA(char * str)
{
   unsigned int hash = 0x01b63a;

   for(; *str; ++str)
   {
      hash = ((hash << 5) + hash) + (*str);
   }
   return hash;	
}

static PPEB NtGetPEB(void)
{
	#ifdef _WIN64
		return (PPEB)__readgsqword(0x60);
	#else
		return (PPEB)__readfsdword(0x30);
	#endif
}

#define KERNEL32_NAME_HASH 0xAD69072A

HMODULE GetKernel32(void)
{
	PLIST_ENTRY CurrentEntry;
	PLDR_DATA_TABLE_ENTRY Current = NULL;
	PPEB Peb = NtGetPEB();

	CurrentEntry = Peb->Ldr->InMemoryOrderModuleList.Flink;

	while (CurrentEntry != &Peb->Ldr->InMemoryOrderModuleList)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (CalcHashW(Current->BaseDllName.Buffer) == KERNEL32_NAME_HASH)
		{
			return Current->DllBase;
		}
		CurrentEntry = CurrentEntry->Flink;
	}
	return NULL;
}

DWORD __stdcall GetAPI(DWORD library, const DWORD APIHASH)
{
	if (library)
	{
		PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)library;
		PIMAGE_NT_HEADERS nt_hdr = (PIMAGE_NT_HEADERS)(library + dos_hdr->e_lfanew);
		PIMAGE_OPTIONAL_HEADER optional_hdr = &nt_hdr->OptionalHeader;
		PIMAGE_DATA_DIRECTORY data_directory = optional_hdr->DataDirectory;
		PIMAGE_EXPORT_DIRECTORY export = (PIMAGE_EXPORT_DIRECTORY)(library + data_directory[0].VirtualAddress);

		DWORD 	*names 		= (DWORD *)(library + export->AddressOfNames);
		WORD 	*ordinals 	= (WORD *)(library + export->AddressOfNameOrdinals);
		DWORD 	*functions 	= (DWORD *)(library + export->AddressOfFunctions);

		for (int i = 0; i < export->NumberOfNames; ++i)
		{
			char *name = (char *)(library + names[i]);
			if (CalcHashA(name) == APIHASH)
				return functions[ordinals[i]] + library;
		}
	}

	return 0;
}

void * CallAPI(DWORD dwHash, DWORD nArgs, ...)
{
	va_list arg_list;
	char *shellcode = VirtualAlloc(NULL, 40, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	va_start(arg_list, nArgs);

	/* push arguments from right to left */
	for (int i = nArgs - 1; i >= 0; --i)
	{
		*(WORD *)	&shellcode[5 * i] = 0x68;	/* opcode of push*/
		*(DWORD *)	&shellcode[5 * i + 1] = va_arg(arg_list, DWORD);	/* what to push */
	}

	va_end(arg_list);

	*(WORD  *)	&shellcode[5 * nArgs] = 0xB8;	/* mov eax, value */
	*(DWORD *)	&shellcode[5 * nArgs + 1] = GetAPI((DWORD)GetKernel32(), dwHash);
	*(WORD  *)	&shellcode[5 * nArgs + 5] = 0xD0FF;	/* call eax */
	*(WORD  *)	&shellcode[5 * nArgs + 7] = 0xC3;	/* ret */

	void * (*p)(void) = (void * (*)(void))shellcode;
	void * ret = p();
	VirtualFree(shellcode, 40, MEM_RELEASE);

	return ret;
}

#pragma code_seg()
