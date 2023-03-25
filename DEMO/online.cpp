#include "stdafx.h"
_NT_BEGIN
#include <Dsgetdc.h>
#include <ntlsa.h>
#include "../inc/ntsam2.h"
#include "../UiConsole/wlog.h"

EXTERN_C
WINBASEAPI
ULONG
WINAPI
NetApiBufferFree (
				  _Frees_ptr_opt_ LPVOID Buffer
				  );

PCSTR GetSidNameUseName(SID_NAME_USE snu)
{
	switch (snu)
	{
	case SidTypeUser: return "User";
	case SidTypeGroup: return "Group";
	case SidTypeDomain: return "Domain";
	case SidTypeAlias: return "Alias";
	case SidTypeWellKnownGroup: return "WellKnownGroup";
	case SidTypeDeletedAccount: return "DeletedAccount";
	case SidTypeInvalid: return "Invalid";
	case SidTypeUnknown: return "Unknown";
	case SidTypeComputer: return "Computer";
	case SidTypeLabel: return "Label";
	case SidTypeLogonSession: return "LogonSession";
	}
	return "?";
}

PCSTR GetProductTypeName(NT_PRODUCT_TYPE NtProductType)
{
	switch (NtProductType)
	{
	case NtProductWinNt: return "WinNt";
	case NtProductLanManNt: return "LanManNt";
	case NtProductServer: return "Server";
	}

	return "?";
}

WLog& PrintSid(_In_ WLog& log, _In_ PSID Sid);

bool OK(_In_ WLog& log, _In_ NTSTATUS status, _In_opt_ PCWSTR msg = 0);

#define Ok(name, ...) OK(log, status = name(__VA_ARGS__), L ## #name)

void DisplayGroups(WLog& log, SAM_HANDLE DomainHandle)
{
	log << L"\t\t<Groups>\r\n";

	NTSTATUS status;
	ULONG Index = 0, TotalAvailable, TotalReturned, ReturnedEntryCount;

	do 
	{
		PVOID Buffer;

		if (Ok(SamQueryDisplayInformation, DomainHandle, DomainDisplayGroup, 
			Index, 0x40, 0x10000, &TotalAvailable, &TotalReturned, &ReturnedEntryCount, &Buffer))
		{
			if (ReturnedEntryCount)
			{
				PDOMAIN_DISPLAY_GROUP pdg = (PDOMAIN_DISPLAY_GROUP)Buffer;
				do 
				{
					log(L"\t\t\t\n<%5u [%08x] '%wZ' '%wZ' />\r\n", pdg->Rid, pdg->Attributes, &pdg->Group, &pdg->Comment);

					Index = pdg->Index;

				} while (pdg++, --ReturnedEntryCount);
			}
			SamFreeMemory(Buffer);
		}

	} while (status == STATUS_MORE_ENTRIES);

	log << L"\t\t</Groups>\r\n";
}

void DisplayAliases(WLog& log, SAM_HANDLE DomainHandle)
{
	log << L"\t\t<Aliases>\r\n";
	NTSTATUS status;
	ULONG CountReturned;
	SAM_ENUMERATE_HANDLE EnumerationContext = 0;
	PSAM_RID_ENUMERATION Buffer;

	do 
	{
		if (Ok(SamEnumerateAliasesInDomain,
			DomainHandle,
			&EnumerationContext,
			&Buffer,
			0x10000,
			&CountReturned))
		{
			if (CountReturned)
			{
				PSAM_RID_ENUMERATION psre = Buffer;
				do 
				{
					log(L"\t\t\t<%5u '%wZ' />\r\n", psre->RelativeId, &psre->Name);

					HANDLE AliasHandle;

					if (Ok(SamOpenAlias, DomainHandle, ALIAS_EXECUTE|ALIAS_READ, psre->RelativeId, &AliasHandle))
					{
						PSID *MemberIds;
						ULONG MemberCount;

						if (Ok(SamGetMembersInAlias, AliasHandle, &MemberIds, &MemberCount))
						{
							if (MemberCount)
							{
								MemberIds += MemberCount;

								do 
								{
									PrintSid(log << L"\t\t\t\t", *--MemberIds) << L"\r\n";
								} while (--MemberCount);
							}

							SamFreeMemory(MemberIds);
						}
						SamCloseHandle(AliasHandle);
					}

				} while (psre++, --CountReturned);
			}
			SamFreeMemory(Buffer);
		}

	} while (status == STATUS_MORE_ENTRIES);

	log << L"\t\t</Aliases>\r\n";
}

void QueryUser(WLog& log, SAM_HANDLE DomainHandle, ULONG UserId)
{
	SAM_HANDLE UserHandle;

	NTSTATUS status;

	if (Ok(SamOpenUser, DomainHandle, USER_READ, UserId, &UserHandle))
	{
		ULONG MembershipCount;

		PGROUP_MEMBERSHIP Groups;

		if (Ok(SamGetGroupsForUser, UserHandle, &Groups, &MembershipCount))
		{
			PVOID buf = Groups;

			if (MembershipCount)
			{
				do 
				{
					log(L" %5u[%X],", Groups->RelativeId, Groups->Attributes);

				} while (Groups++, --MembershipCount);
			}

			SamFreeMemory(buf);
		}

		SamCloseHandle(UserHandle);
	}
}

void DisplayUsers(WLog& log, SAM_HANDLE DomainHandle)
{
	log << L"\t\t<Users>\r\n";
	NTSTATUS status;
	ULONG Index = 0, TotalAvailable, TotalReturned, ReturnedEntryCount;

	do 
	{
		PVOID Buffer;
		if (Ok(SamQueryDisplayInformation, DomainHandle, DomainDisplayUser, 
			Index, 0x40, 0x10000, &TotalAvailable, &TotalReturned, &ReturnedEntryCount, &Buffer))
		{
			if (ReturnedEntryCount)
			{
				PDOMAIN_DISPLAY_USER pdu = (PDOMAIN_DISPLAY_USER)Buffer;
				do 
				{
					log(L"\t\t\t\t<%5u [%08x] '%wZ' '%wZ' /> G {", pdu->Rid, pdu->AccountControl, &pdu->LogonName, &pdu->FullName);

					QueryUser(log, DomainHandle, pdu->Rid);

					log << L" }\r\n";

					Index = pdu->Index;

				} while (pdu++, --ReturnedEntryCount);
			}
			SamFreeMemory(Buffer);
		}

	} while (status == STATUS_MORE_ENTRIES);

	log << L"\t\t</Users>\r\n";
}

void DumpDomain(WLog& log, SAM_HANDLE ServerHandle, PSID DomainSid)
{
	SAM_HANDLE DomainHandle;

	NTSTATUS status;

	PrintSid(log << L"\t<Domain: ", DomainSid) << L" >\r\n";

	if (Ok(SamOpenDomain, ServerHandle, DOMAIN_READ|DOMAIN_EXECUTE, DomainSid, &DomainHandle))
	{
		DisplayGroups(log, DomainHandle);
		DisplayAliases(log, DomainHandle);
		DisplayUsers(log, DomainHandle);

		SamCloseHandle(DomainHandle);
	}

	PrintSid(log << L"\t</Domain: ", DomainSid) << L" >\r\n";
}

void DumpSam(WLog& log, PWSTR DomainControllerAddress, PSID DomainSid)
{
	UNICODE_STRING ServerName;
	RtlInitUnicodeString(&ServerName, DomainControllerAddress);

	SAM_HANDLE ServerHandle;

	NTSTATUS status;

	log(L"SamConnect(%wZ)\r\n", &ServerName);

	if (Ok(SamConnect, &ServerName, &ServerHandle, SAM_SERVER_LOOKUP_DOMAIN, 0))
	{
		static const SID BuiltinDomainSid = {
			SID_REVISION, 1, SECURITY_NT_AUTHORITY, { SECURITY_BUILTIN_DOMAIN_RID }
		};

		DumpDomain(log, ServerHandle, DomainSid);
		DumpDomain(log, ServerHandle, const_cast<SID*>(&BuiltinDomainSid));

		SamCloseHandle(ServerHandle);
	}
}

void QueryRemoteDC(WLog& log, PCUNICODE_STRING Name, PSID DomainSid)
{
	ULONG Length = Name->Length;
	PWSTR DomainName = Name->Buffer;
	if (Length >= Name->MaximumLength)
	{
		PWSTR buf = (PWSTR)alloca(Length + sizeof(WCHAR));
		memcpy(buf, DomainName, Length);
		DomainName = buf;
	}

	*(PWSTR)RtlOffsetToPointer(DomainName, Length) = 0;

	PDOMAIN_CONTROLLER_INFO DomainControllerInfo;

	if (ULONG dwError = DsGetDcNameW(0, DomainName, 0, 0, DS_IP_REQUIRED|DS_PDC_REQUIRED, &DomainControllerInfo))
	{
		log(L"DsGetDcNameW = %u\r\n", dwError);
		log[HRESULT_FROM_WIN32(dwError)];
	}
	else
	{
		log(L"DC = %s\r\nIP = %s\r\n", DomainControllerInfo->DomainControllerName + 2, DomainControllerInfo->DomainControllerAddress + 2);
		DumpSam(log, DomainControllerInfo->DomainControllerAddress + 2, DomainSid);
		NetApiBufferFree(DomainControllerInfo);
	}
}

void Online(WLog& log)
{
	NT_PRODUCT_TYPE NtProductType;
	RtlGetNtProductType(&NtProductType);

	log(L"NtProduct%S\r\n", GetProductTypeName(NtProductType));

	OBJECT_ATTRIBUTES oa = { sizeof(oa) };
	LSA_HANDLE PolicyHandle;
	NTSTATUS status;
	
	if (Ok(LsaOpenPolicy, 0, &oa, POLICY_VIEW_LOCAL_INFORMATION|POLICY_LOOKUP_NAMES, &PolicyHandle))
	{
		union {
			PVOID buf;
			PPOLICY_ACCOUNT_DOMAIN_INFO padi;
			PPOLICY_DNS_DOMAIN_INFO pddi;
		};

		if (Ok(LsaQueryInformationPolicy, PolicyHandle, PolicyDnsDomainInformation, &buf))
		{
			log(L"Domain=%wZ ( %wZ ), Forest=%wZ\r\n", &pddi->Name, &pddi->DnsDomainName, &pddi->DnsForestName);

			if (PSID DomainSid = pddi->Sid)
			{
				if (NtProductType != NtProductLanManNt)
				{
					QueryRemoteDC(log, &pddi->Name, DomainSid);
				}
				else
				{
					DumpSam(log, 0, DomainSid);
				}
			}

			LsaFreeMemory(buf);
		}

		if (NtProductType != NtProductLanManNt)
		{
			if (Ok(LsaQueryInformationPolicy, PolicyHandle, PolicyAccountDomainInformation, &buf))
			{
				DumpSam(log, 0, padi->DomainSid);

				LsaFreeMemory(buf);
			}
		}

		LsaClose(PolicyHandle);
	}
}

_NT_END