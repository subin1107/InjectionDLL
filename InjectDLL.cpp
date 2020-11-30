#include "windows.h"
#include "tchar.h"

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hMod = NULL;
	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath)+1)*sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc;

	//#1. dwPID를 이용하여 대상 프로세스(notepad.exe)의 HANDLE을 구한다.
	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		_tprintf(L"OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
		return FALSE;
	}

	//#2. 대상 프로세스(notepad.exe) 메모리에 szDllPath 크기만큼 메모리를 할당한다.
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

	//#3. 할당받은 메모리에 myhack.dll 경로 ("c:\\myhack.dll")를 쓴다.
	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);

	//#4. LoadLibraryW() API 주소를 구한다.
	hMod = LoadLibrary(L"kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");

	//#5. notepad.exe 프로세스에 스레드를 실행한다.
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
		_tprintf(L"InjectDll(\"%s\") 성공했습니다! n", argv[2]);
	else
		_tprintf(L"InjectDll(\"%s\") 실패했습니다!\n", argv[2]);

	return 0;

}