#pragma once

#include "Win32.h"
#include <stdio.h>

typedef struct {
	DWORD32 key;
	DWORD64	payload_len;
	PBYTE	payload;
} RSRC, *PRSRC;

PRSRC	ExtractResources(VOID);
VOID	Inject(DWORD pid);
