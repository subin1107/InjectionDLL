#include "windows.h"
#include "tchar.h"

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hMod = NULL;
	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath)+1)*sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc;

	//#1. dwPID�� �̿��Ͽ� ��� ���μ���(notepad.exe)�� HANDLE�� ���Ѵ�.
	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		_tprintf(L"OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
		return FALSE;
	}

	//#2. ��� ���μ���(notepad.exe) �޸𸮿� szDllPath ũ�⸸ŭ �޸𸮸� �Ҵ��Ѵ�.
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

	//#3. �Ҵ���� �޸𸮿� myhack.dll ��� ("c:\\myhack.dll")�� ����.
	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);

	//#4. LoadLibraryW() API �ּҸ� ���Ѵ�.
	hMod = LoadLibrary(L"kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");

	//#5. notepad.exe ���μ����� �����带 �����Ѵ�.
	hThread = CreateRemoteThread(hProcess,  //hProcess
		NULL, // IpThreadAttributes
		0, //dwStackSize
		pThreadProc, //IpStartAddress
		pRemoteBuf, //IpParameter
		0,     //dwCreationFlags
		NULL); //IpThreadId


	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;

}

int _tmain(int argc, TCHAR* argv[])
{
	if (argc != 3) {
		_tprintf(L"USAGE : %s pid dll_path\n", argv[0]);
		return 1;
	}
	//injection dll
	if (InjectDll((DWORD)_tstol(argv[1]), argv[2]))
		_tprintf(L"InjectDll(\"%s\") �����߽��ϴ�! n", argv[2]);
	else
		_tprintf(L"InjectDll(\"%s\") �����߽��ϴ�!\n", argv[2]);

	return 0;

}