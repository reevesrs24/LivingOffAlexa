#include <unordered_map>
#include "PELoader.h"


PELoader::PELoader()
{
	hFile = NULL;
	pDosHeader = NULL;
	pNTHeader = NULL;
}



bool PELoader::loadPEFromDisk(LPCSTR fileName)
{

	hFile = CreateFileA(
		fileName,
		GENERIC_READ,
		NULL,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		// printf("Error opening file: %i", GetLastError());
		return false;
	}

	DWORD dwFileSize = GetFileSize(hFile, NULL);

	PBYTE pbBuffer = new BYTE[dwFileSize];
	PDWORD pdwNumberOfBytesRead = NULL;

	if (!ReadFile(hFile, pbBuffer, dwFileSize, pdwNumberOfBytesRead, NULL))
	{

		//printf("Error reading file: %i", GetLastError());
		return false;

	}

	pDosHeader = (PIMAGE_DOS_HEADER)pbBuffer;

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		//printf("Failed: .exe does not have a valid DOS signature %i", GetLastError());
		return false;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	LPVOID lpImageBaseAddress = VirtualAlloc(NULL, pNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


	copyPESections(lpImageBaseAddress);
	processReloc(lpImageBaseAddress);
	processIData(lpImageBaseAddress);
	processDIData(lpImageBaseAddress);
	executeLoadedPE(lpImageBaseAddress);

}

bool PELoader::loadPEFromMemory(PBYTE pbBuffer)
{

	pDosHeader = (PIMAGE_DOS_HEADER)pbBuffer;

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		//printf("Failed: .exe does not have a valid DOS signature %i", GetLastError());
		return false;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	LPVOID lpImageBaseAddress = VirtualAlloc(NULL, pNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


	copyPESections(lpImageBaseAddress);
	processReloc(lpImageBaseAddress);
	processIData(lpImageBaseAddress);
	processDIData(lpImageBaseAddress);
	executeLoadedPE(lpImageBaseAddress);

}


bool PELoader::copyPESections(LPVOID lpImageBaseAddress)
{

	DWORD dwOldProtection;

	std::unordered_map<int, int> sectionMemoryProtection;
	sectionMemoryProtection.insert(std::make_pair(0x2, PAGE_EXECUTE));
	sectionMemoryProtection.insert(std::make_pair(0x4, PAGE_READONLY));
	sectionMemoryProtection.insert(std::make_pair(0x6, PAGE_EXECUTE_READ));
	sectionMemoryProtection.insert(std::make_pair(0xC, PAGE_READWRITE));
	sectionMemoryProtection.insert(std::make_pair(0xE, PAGE_EXECUTE_READWRITE));


	if (!CopyMemory(
		lpImageBaseAddress,
		pDosHeader,
		pNTHeader->OptionalHeader.SizeOfHeaders)
		)
	{
		//printf("Failed: Unable to write headers: %i", GetLastError());
		return false;
	}

	// Set Header memory protection to PAGE_READONLY
	VirtualProtect(
		(LPVOID)lpImageBaseAddress,
		pNTHeader->OptionalHeader.SizeOfHeaders,
		PAGE_READONLY,
		&dwOldProtection
	);

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);

	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
	{
		//printf("Copying data from: %s\n", pSectionHeader->Name);

		if (!CopyMemory(
			(LPVOID)((DWORD)lpImageBaseAddress + (DWORD)pSectionHeader->VirtualAddress),
			(PVOID)((DWORD)pDosHeader + (DWORD)pSectionHeader->PointerToRawData),
			(DWORD)pSectionHeader->SizeOfRawData)
			)
		{
			//printf("Failed copying data from %s: %i", pSectionHeader->Name, GetLastError());
			return false;
		}

		// Set the section correct memory protection
		VirtualProtect(
			(LPVOID)((DWORD)lpImageBaseAddress + (DWORD)pSectionHeader->VirtualAddress),
			(DWORD)pSectionHeader->SizeOfRawData,
			sectionMemoryProtection[(pSectionHeader->Characteristics >> 28)],
			&dwOldProtection
		);

		pSectionHeader++;
	}

}

bool PELoader::processReloc(LPVOID lpImageBaseAddress)
{

	DWORD dwOldProtection;

	// Get Pointer to the relocation data directory
	PIMAGE_DATA_DIRECTORY pBaseReloc = (PIMAGE_DATA_DIRECTORY)&pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	DWORD dwImageBaseDifference = (DWORD)lpImageBaseAddress - (DWORD)pNTHeader->OptionalHeader.ImageBase;

	PIMAGE_BASE_RELOCATION pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)lpImageBaseAddress + (DWORD)pBaseReloc->VirtualAddress);

	PBASE_RELOCATION_BLOCK pRelocationBlock = (PBASE_RELOCATION_BLOCK)pImageBaseRelocation;

	// Number of relocations needed per block
	DWORD relocationCount = (pImageBaseRelocation->SizeOfBlock - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_FIXUP);

	PBASE_RELOCATION_FIXUP pBaseRelocationFixup = (PBASE_RELOCATION_FIXUP)((DWORD)pRelocationBlock + sizeof(BASE_RELOCATION_BLOCK));

	do {


		for (int i = 0; i < relocationCount; i++) {

			if (pBaseRelocationFixup->Type == IMAGE_REL_BASED_HIGHLOW)
			{

				VirtualProtect((PVOID)((DWORD)lpImageBaseAddress + (DWORD)pRelocationBlock->PageRVA + (DWORD)pBaseRelocationFixup->Offset), sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtection);

				PDWORD pdwRelocation = (PDWORD)((DWORD)lpImageBaseAddress + (DWORD)pRelocationBlock->PageRVA + (DWORD)pBaseRelocationFixup->Offset);

				*pdwRelocation += dwImageBaseDifference;

				VirtualProtect((PVOID)((DWORD)lpImageBaseAddress + (DWORD)pRelocationBlock->PageRVA + (DWORD)pBaseRelocationFixup->Offset), sizeof(DWORD), dwOldProtection, &dwOldProtection);

			}

			pBaseRelocationFixup += 1;

		}

		pRelocationBlock = (PBASE_RELOCATION_BLOCK)((DWORD)pRelocationBlock + (DWORD)pRelocationBlock->BlockSize);
		relocationCount = (pRelocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_FIXUP);
		pBaseRelocationFixup = (PBASE_RELOCATION_FIXUP)((DWORD)pRelocationBlock + sizeof(BASE_RELOCATION_BLOCK));

	} while (pRelocationBlock->BlockSize);


	return true;
}

bool PELoader::processIData(LPVOID lpImageBaseAddress)
{
	pDosHeader = (PIMAGE_DOS_HEADER)lpImageBaseAddress;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR pImpDecsriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pDosHeader + (DWORD)pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (pImpDecsriptor->Name) {
		DWORD dwOldProtection;

		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((DWORD)lpImageBaseAddress + (DWORD)pImpDecsriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pThunkFirst = (PIMAGE_THUNK_DATA)((DWORD)lpImageBaseAddress + (DWORD)pImpDecsriptor->FirstThunk);
		LPSTR lpDllName = (LPSTR)((DWORD)lpImageBaseAddress + (DWORD)pImpDecsriptor->Name);

		// printf("%s\n", lpDllName);
		HMODULE dllHMod = LoadLibraryA(lpDllName);
		HANDLE procAddr = NULL;

		while (pThunk->u1.AddressOfData) {

			if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
			{
				// printf("\tOrdinal: %x\n", (LPCSTR)(pThunk->u1.Ordinal & 0xFFFF));
				procAddr = GetProcAddress(dllHMod, (LPCSTR)(pThunk->u1.Ordinal & 0xFFFF));
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pImage = (PIMAGE_IMPORT_BY_NAME)((DWORD)lpImageBaseAddress + (DWORD)pThunk->u1.Function);
				procAddr = GetProcAddress(dllHMod, pImage->Name);
				// printf("\t%s\n", pImage->Name);
			}


			VirtualProtect(&pThunkFirst->u1.Function, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtection);
			pThunkFirst->u1.Function = (DWORD)procAddr;
			VirtualProtect(&pThunkFirst->u1.Function, sizeof(DWORD), dwOldProtection, &dwOldProtection);

			pThunk++;
			pThunkFirst++;
		}

		pImpDecsriptor++;
	}

	return true;
}

bool PELoader::processDIData(LPVOID lpImageBaseAddress)
{


	PIMAGE_DELAYLOAD_DESCRIPTOR pDelayLoadImportDirectory = (PIMAGE_DELAYLOAD_DESCRIPTOR)((DWORD)lpImageBaseAddress + (DWORD)pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);

	while (pDelayLoadImportDirectory->DllNameRVA) {
		DWORD dwOldProtection;

		PIMAGE_THUNK_DATA pThunkDelayed = (PIMAGE_THUNK_DATA)((DWORD)lpImageBaseAddress + (DWORD)pDelayLoadImportDirectory->ImportAddressTableRVA);
		PIMAGE_THUNK_DATA pThunkDelayedFirst = (PIMAGE_THUNK_DATA)((DWORD)lpImageBaseAddress + (DWORD)pDelayLoadImportDirectory->ImportNameTableRVA);
		LPSTR lpDllDelayedName = (LPSTR)((DWORD)lpImageBaseAddress + (DWORD)pDelayLoadImportDirectory->DllNameRVA);


		//printf("%s\n", lpDllDelayedName);
		HMODULE hModDllDelayed = LoadLibraryA(lpDllDelayedName);
		if (hModDllDelayed == NULL) break;
		HANDLE procAddr = NULL;

		while (pThunkDelayed->u1.AddressOfData) {



			if (pThunkDelayedFirst->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
			{
				//printf("\tOrdinal: %x\n", (LPCSTR)(pThunkDelayedFirst->u1.Ordinal & 0xFFFF));
				procAddr = GetProcAddress(hModDllDelayed, (LPCSTR)(pThunkDelayedFirst->u1.Ordinal & 0xFFFF));
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pImage = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDosHeader + (DWORD)pThunkDelayedFirst->u1.Function);
				//printf("\t%s\n", pImage->Name);
				procAddr = GetProcAddress(hModDllDelayed, pImage->Name);
			}


			VirtualProtect(&pThunkDelayed->u1.Function, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtection);
			pThunkDelayed->u1.Function = (DWORD)procAddr;
			VirtualProtect(&pThunkDelayed->u1.Function, sizeof(DWORD), dwOldProtection, &dwOldProtection);

			pThunkDelayed++;
			pThunkDelayedFirst++;
		}

		pDelayLoadImportDirectory++;
	}

	return true;

}



void PELoader::executeLoadedPE(LPVOID lpImageBaseAddress)
{

	DWORD dwImageBaseAddress = (DWORD)lpImageBaseAddress + pNTHeader->OptionalHeader.AddressOfEntryPoint;

	(*(void(*)())dwImageBaseAddress)();

}