#include "stdafx.h"
#include "resource.h"

_NT_BEGIN
#include "../UiConsole/GuiLog.h"
#include "../UiConsole/wlog.h"

PCWSTR WINAPI GetWindowName()
{
	return L"Sam Offline";
}

PCWSTR WINAPI GetIconName()
{
	return MAKEINTRESOURCEW(IDI_ICON1);
}

HINSTANCE WINAPI GetIconModule()
{
	return (HINSTANCE)&__ImageBase;
}

bool OK(_In_ WLog& log, _In_ NTSTATUS status, _In_opt_ PCWSTR msg = 0)
{
	if (0 > status)
	{
		if (msg)
		{
			log(L"!! %s = %x\r\n", msg, status);
		}
		log[HRESULT_FROM_NT(status)];
		return false;
	}

	return true;
}

WLog& PrintSid(_In_ WLog& log, _In_ PSID Sid)
{
	WCHAR buf[SECURITY_MAX_SID_STRING_CHARACTERS];
	UNICODE_STRING str = {0, sizeof(buf), buf };
	if (0 <= RtlConvertSidToUnicodeString(&str, Sid, FALSE))
	{
		log(L"%wZ", &str);
	}
	return log;
}

void OfflineTest(_In_ WLog& log, _In_ PCWSTR FileName);
void Online(WLog& log);

BOOL WINAPI ep_work(_In_ HWND hwnd)
{
	WLog log;

	if (NOERROR == log.Init(0x100000))
	{
		if (PCWSTR FileName = wcschr(GetCommandLineW(), '*'))
		{
			if (*++FileName)
			{
				OfflineTest(log, FileName);
			}
			else
			{
				Online(log);
			}
		}
		else
		{
			log << L"Invalid command line !\r\n*[path to sam file] must be!\r\n";
		}

		log >> hwnd;

		return TRUE;
	}

	return FALSE;
}

_NT_END