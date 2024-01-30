#include "Win32.h"

HMODULE GetModuleByHash(DWORD32 hash)
{
    PLDR_MODULE     LDTEntry;
    PLIST_ENTRY     Head;
    PLIST_ENTRY     Current;
    PPEB            PEB;

#ifdef _M_IX86
    PEB     = (PPEB)__readfsdword(0x30)
#else
    PEB     = (PPEB)__readgsqword(0x60);
#endif
    Head    = (PLIST_ENTRY)&PEB->LoaderData->InLoadOrderModuleList;
    Current = (PLIST_ENTRY)Head->Flink;

    do {
        CHAR ModuleName[256] = { 0 };


        LDTEntry = (PLDR_MODULE)Current;

        WCharStringToCharString(ModuleName, LDTEntry->BaseDllName.Buffer, LDTEntry->BaseDllName.Length);
        
        ToLowerStringA(ModuleName);

        if (GetHash(ModuleName) == hash || !hash )
        {
            return (HMODULE)LDTEntry->BaseAddress;
        }

        Current = (PLIST_ENTRY)Current->Flink;
    
    } while (Current != Head);

	return (NULL);
}


FARPROC GetProcAddressByHash(HMODULE hModule, DWORD32 hash)
{
    PBYTE                   ImageBase           = (PBYTE)hModule;
    HMODULE                 fwdModule           = NULL;
    FARPROC                 ProcAddress         = NULL;
    PCHAR                   DotPtr              = NULL;
    CHAR                    Library[MAX_PATH]   = { 0 };
    CHAR                    Function[MAX_PATH]  = { 0 };
    PIMAGE_DOS_HEADER       DosHdr              = (PIMAGE_DOS_HEADER) ImageBase;
    PIMAGE_NT_HEADERS       NtHdr               = (PIMAGE_NT_HEADERS)       (ImageBase + DosHdr->e_lfanew);
    PIMAGE_OPTIONAL_HEADER  OptHdr              = (PIMAGE_OPTIONAL_HEADER) & (NtHdr->OptionalHeader);
    PIMAGE_DATA_DIRECTORY   ExportDataDir       = (PIMAGE_DATA_DIRECTORY) & (OptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    PIMAGE_EXPORT_DIRECTORY ExportDir           = (PIMAGE_EXPORT_DIRECTORY)(ImageBase + ExportDataDir->VirtualAddress);

    PDWORD pEAT                 = (PDWORD)(ImageBase + ExportDir->AddressOfFunctions);
    PDWORD pFunctionNameTable   = (PDWORD)(ImageBase + ExportDir->AddressOfNames);
    PWORD  pOrdinals            = (PWORD)(ImageBase + ExportDir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < ExportDir->NumberOfNames; i++)
    {
        PSTR ExportName = (PSTR)(ImageBase + pFunctionNameTable[i]);
        
        if (GetHash(ExportName) == hash)
        {
            ProcAddress = (FARPROC) (ImageBase + pEAT[pOrdinals[i]]);
            break;
        }
    }
    
    if ((PBYTE)ProcAddress >= (PBYTE)ExportDir &&
            (PBYTE)ProcAddress < (PBYTE)(ExportDir + ExportDataDir->Size))
    {
        CHAR    fwdFunction[MAX_PATH]   = { 0 };
    
        memcpy(fwdFunction, (PCHAR)ProcAddress, strlen((PCHAR)ProcAddress));

        DotPtr  = strchr((PCHAR)fwdFunction, '.');

        if (DotPtr)
            *DotPtr = 0;

        memcpy(Library, fwdFunction, strlen(fwdFunction));
        memcpy(Function, DotPtr + 1, strlen(DotPtr + 1));

        fwdModule = LoadModule(Library);

        if (fwdModule)
            ProcAddress = GetProcAddressByHash(fwdModule, GetHash(Function));
    }

    return (FARPROC)ProcAddress;
}

HMODULE LoadModule(LPSTR module)
{
    HANDLE          hModule;
    HMODULE         hNtdll;
    UNICODE_STRING  ModuleName = { 0 };
    WCHAR           ModuleNameW[MAX_PATH] = { 0 };

    hNtdll = GetModuleByHash(NTDLL);

    if (hNtdll)
    {
        RtlInitUnicodeString_t  RtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddressByHash(hNtdll, RTL_INIT_UNICODE);
        LdrLoadDll_t            LdrLoadDll = (LdrLoadDll_t)GetProcAddressByHash(hNtdll, LDR_LOAD_DLL);
        
        if (RtlInitUnicodeString && LdrLoadDll)
        {
            CharStringToWCharString(ModuleNameW, module, strlen(module));

            RtlInitUnicodeString(&ModuleName, ModuleNameW);

            if (NT_SUCCESS(LdrLoadDll(NULL, 0, &ModuleName, &hModule)))
                return ((HMODULE)hModule);
            else
    	        return (NULL);
        }

    }
    
    return (NULL);

}

PIMAGE_SECTION_HEADER GetSection(HMODULE hModule, PCSTR sectionName)
{
    PBYTE               ImageBase = (PBYTE)hModule;
    PIMAGE_DOS_HEADER   DosHdr = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS   NtHdr = (PIMAGE_NT_HEADERS)(ImageBase + DosHdr->e_lfanew);

    for (WORD i = 0; i < NtHdr->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER SectionHdr = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(NtHdr) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((PCSTR)SectionHdr->Name, sectionName))
        {
            return (SectionHdr);
        }
    }
    return (NULL);
}

DWORD GetPid(LPCSTR pname) {

    HANDLE              hProcSnap;
    PROCESSENTRY32      pe32;
    int pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (INVALID_HANDLE_VALUE == hProcSnap)
        return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiA(pname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);

    return pid;
}

VOID    XOR(PBYTE data, DWORD data_len, PBYTE key, DWORD key_len)
{
    for (DWORD i = 0; i < data_len; i++)
    {
        data[i] = data[i] ^ key[i % key_len];
    }
}

DWORD32 GetHash(PSTR str)
{
    DWORD32 Hash;
    SIZE_T  idx;

    Hash = 0;
    idx = 0;
    while (str[idx])
        Hash = str[idx++] + ((Hash >> 10) | (Hash << 8));
    return Hash;
}


PCHAR ToLowerStringA(_In_ PCHAR Ptr)
{
    PCHAR sv = Ptr;
    while (*sv != '\0')
    {
        if (*sv >= 'A' && *sv <= 'Z')
            *sv = *sv + ('a' - 'A');

        sv++;
    }
    return Ptr;
}

SIZE_T CharStringToWCharString(_Inout_ PWCHAR Destination, _In_ PCHAR Source, SIZE_T _In_ MaximumAllowed)
{
    INT Length = (INT)MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

SIZE_T WCharStringToCharString(_Inout_ PCHAR Destination, _In_ PWCHAR Source, _In_ SIZE_T MaximumAllowed)
{
    INT Length = (INT)MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}
