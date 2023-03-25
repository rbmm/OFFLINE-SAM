#include "stdafx.h"
#include "resource.h"

_NT_BEGIN
#include "../inc/samoffline.h"
#include "../UiConsole/GuiLog.h"
#include "../UiConsole/wlog.h"

bool OK(_In_ WLog& log, _In_ NTSTATUS status, _In_opt_ PCWSTR msg = 0);

WLog& PrintSid(_In_ WLog& log, _In_ PSID Sid);

void DumpAlias(_In_ WLog& log, _In_ SAM_HANDLE AliasHandle)
{
	PSID *MemberIds;
	ULONG MemberCount;

	NTSTATUS status = SamOfflineGetMembersInAlias(AliasHandle, &MemberIds, &MemberCount);

	if (OK(log, status, L"GetMembersInAlias"))
	{
		if (MemberCount)
		{
			MemberIds += MemberCount;
			do 
			{
				PrintSid(log << L"\t\t", *--MemberIds) << L"\r\n";

			} while (--MemberCount);
		}
		SamOfflineFreeMemory(MemberIds);
	}
}

void DumpAliases(_In_ WLog& log, _In_ SAM_HANDLE DomainHandle, _In_ PSAM_RID_ENUMERATION Buffer, _In_ ULONG CountReturned)
{
	do 
	{
		SAM_HANDLE AliasHandle;
		NTSTATUS status = SamOfflineOpenAlias(DomainHandle, Buffer->RelativeId, &AliasHandle);

		log(L"\tOpenAlias(%u \"%wZ\")=%x\r\n", Buffer->RelativeId, &Buffer->Name, status);

		if (OK(log, status))
		{
			DumpAlias(log, AliasHandle);
			SamOfflineCloseHandle(AliasHandle);
		}

	} while (Buffer++, --CountReturned);
}

void EnumAliases(_In_ WLog& log, _In_ SAM_HANDLE DomainHandle)
{
	SAM_ENUMERATE_HANDLE EnumerationContext = 0;
	PSAM_RID_ENUMERATION Buffer;
	NTSTATUS status;
	ULONG CountReturned;

	do 
	{
		status = SamOfflineEnumerateAliasesInDomain(DomainHandle, &EnumerationContext, &Buffer, 0x100, &CountReturned);

		if (OK(log << L"\tAliases:\r\n", status))
		{
			if (CountReturned)
			{
				DumpAliases(log, DomainHandle, Buffer, CountReturned);
			}
			SamOfflineFreeMemory(Buffer);
		}

	} while (STATUS_MORE_ENTRIES == status);
}

void DumpUser(_In_ WLog& log, _In_ SAM_HANDLE UserHandle)
{
	union {
		PVOID buf;
		PUSER_ADMIN_COMMENT_INFORMATION pac;
	};

	//  only this valid here:
	//	UserExtendedInformation
	//	UserControlInformation
	//	UserAdminCommentInformation
	//	UserFullNameInformation
	//	UserAccountNameInformation
	//	UserPreferencesInformation
	NTSTATUS status = SamOfflineQueryInformationUser(UserHandle, UserAdminCommentInformation, &buf);

	if (OK(log, status))
	{
		log(L"\t\t\"%wZ\"\r\n", &pac->AdminComment);
		SamOfflineFreeMemory(buf);
	}
}

void DumpUsers(_In_ WLog& log, _In_ SAM_HANDLE DomainHandle, _In_ PSAM_RID_ENUMERATION Buffer, _In_ ULONG CountReturned)
{
	do 
	{
		SAM_HANDLE UserHandle;
		NTSTATUS status = SamOfflineOpenUser(DomainHandle, Buffer->RelativeId, &UserHandle);

		log(L"\tOpenUser(%u \"%wZ\")=%x\r\n", Buffer->RelativeId, &Buffer->Name, status);

		if (OK(log, status))
		{
			DumpUser(log, UserHandle);
			SamOfflineCloseHandle(UserHandle);
		}

	} while (Buffer++, --CountReturned);
}

void EnumUsers(_In_ WLog& log, _In_ SAM_HANDLE DomainHandle)
{
	SAM_ENUMERATE_HANDLE EnumerationContext = 0;
	PSAM_RID_ENUMERATION Buffer;
	NTSTATUS status;
	ULONG CountReturned;

	do 
	{
		status = SamOfflineEnumerateUsersInDomain2(DomainHandle, &EnumerationContext, 0, &Buffer, 0x100, &CountReturned);

		if (OK(log << L"\tUsers:\r\n", status))
		{
			if (CountReturned)
			{
				DumpUsers(log, DomainHandle, Buffer, CountReturned);
			}
			SamOfflineFreeMemory(Buffer);
		}

	} while (STATUS_MORE_ENTRIES == status);
}

void OfflineTest(_In_ WLog& log, _In_ SAM_HANDLE ServerHandle, _In_ PSAM_SID_ENUMERATION Buffer, _In_ ULONG CountReturned)
{
	NTSTATUS status;
	SAM_HANDLE DomainHandle;
	do 
	{
		PSID DomainId;
		
		status = SamOfflineLookupDomainInSamServer(ServerHandle, &Buffer->Name, &DomainId);

		if (OK(log(L"LookupDomain(%wZ)=%x\r\n", &Buffer->Name, status), status))
		{
			status = SamOfflineOpenDomain(ServerHandle, DomainId, &DomainHandle);

			PrintSid(log << L"\tOpenDomain(", DomainId)(L")=%x\r\n", status);

			SamOfflineFreeMemory(DomainId);

			if (OK(log, status))
			{
				EnumAliases(log, DomainHandle);
				EnumUsers(log, DomainHandle);
				SamOfflineCloseHandle(DomainHandle);
			}
		}

	} while (Buffer++, --CountReturned);
}

void OfflineTest(_In_ WLog& log, _In_ PCWSTR FileName)
{
	SAM_HANDLE ServerHandle;

	NTSTATUS status = SamOfflineConnect(FileName, &ServerHandle);

	log(L"SamOfflineConnect(\"%s\")=%x\r\n", FileName, status);

	if (OK(log, status))
	{
		PSAM_SID_ENUMERATION Buffer;
		SAM_ENUMERATE_HANDLE EnumerationContext = 0;
		ULONG CountReturned;

		do 
		{
			status = SamOfflineEnumerateDomainsInSamServer(ServerHandle, &EnumerationContext, &Buffer, 0x100, &CountReturned);

			if (OK(log << L"Domains:\r\n", status))
			{
				if (CountReturned)
				{
					OfflineTest(log, ServerHandle, Buffer, CountReturned);
				}

				SamOfflineFreeMemory(Buffer);
			}

		} while (STATUS_MORE_ENTRIES == status);

		SamOfflineCloseHandle(ServerHandle);
	}
}

_NT_END
