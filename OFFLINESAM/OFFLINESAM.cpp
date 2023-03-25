#define CONST const
#define EXTERN_C       extern "C"
#define EXTERN_C_START extern "C" {
#define EXTERN_C_END   }
#define _Out_ 
#define _Deref_post_count_(Count)
#define _In_
#define _Outptr_
#define _Inout_
#define _In_reads_(Count)

#define NTAPI __stdcall
#define NTSYSAPI 

typedef wchar_t WCHAR;
typedef CONST WCHAR *LPCWSTR, *PCWSTR;
typedef void *PVOID;
typedef PVOID SAM_HANDLE, *PSAM_HANDLE;
typedef unsigned long ULONG, *PULONG;
typedef long LONG, NTSTATUS, *PNTSTATUS;
typedef ULONG SAM_ENUMERATE_HANDLE, *PSAM_ENUMERATE_HANDLE;

struct SAM_SID_ENUMERATION;

typedef SAM_SID_ENUMERATION *PSAM_SID_ENUMERATION;

struct UNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef PVOID PSID;

enum SID_NAME_USE;
enum ALIAS_INFORMATION_CLASS;
enum USER_INFORMATION_CLASS;

typedef SID_NAME_USE *PSID_NAME_USE;

struct SAM_RID_ENUMERATION;

typedef SAM_RID_ENUMERATION *PSAM_RID_ENUMERATION;

EXTERN_C_START

// Windows::Rtl::IRtlSystemIsolationLayer
struct IRtlSystemIsolationLayer;

//////////////////////////////////////////////////////////////////////////
// Basic

NTSYSAPI
void
NTAPI
SamOfflineCloseHandle(
					  _In_ SAM_HANDLE SamHandle
					  ){}

NTSYSAPI
void
NTAPI
SamOfflineFreeMemory(
					 _In_ PVOID Buffer
					 ){}

//////////////////////////////////////////////////////////////////////////
// Server

NTSYSAPI
void 
NTAPI 
SamOfflineConnect(
				  _In_ PCWSTR FileName, 
				  _Out_ PSAM_HANDLE ServerHandle
				  ){}

NTSYSAPI
void
NTAPI
SamOfflineConnectExternal(
						  _In_ PCWSTR,
						  _In_ PCWSTR,
						  _In_ PCWSTR,
						  _In_ PCWSTR,
						  _Out_ PSAM_HANDLE ServerHandle
						  ){}

NTSYSAPI
void
NTAPI
SamOfflineConnectForInstaller(
							  _In_ IRtlSystemIsolationLayer*,
							  _Out_ PSAM_HANDLE ServerHandle
							  ){}

NTSYSAPI
void
NTAPI
SamOfflineEnumerateDomainsInSamServer(
									  _In_ SAM_HANDLE ServerHandle,
									  _Inout_ PSAM_ENUMERATE_HANDLE EnumerationContext,
									  _Outptr_ PSAM_SID_ENUMERATION *Buffer, // 
									  _In_ ULONG PreferedMaximumLength,
									  _Out_ PULONG CountReturned
									  ){}

NTSYSAPI
void
NTAPI
SamOfflineLookupDomainInSamServer(
								  _In_ SAM_HANDLE ServerHandle,
								  _In_ PCUNICODE_STRING Name,
								  _Outptr_ PSID *DomainId
								  ){}

//////////////////////////////////////////////////////////////////////////
// Domain

NTSYSAPI
void
NTAPI
SamOfflineOpenDomain(
					 _In_ SAM_HANDLE ServerHandle,
					 _In_ PSID DomainId,
					 _Out_ PSAM_HANDLE DomainHandle
					 ){}

NTSYSAPI
void
NTAPI
SamOfflineRidToSid(
				   _In_ SAM_HANDLE DomainHandle,
				   _In_ ULONG Rid,
				   _Outptr_ PSID *Sid
				   ){}

NTSYSAPI
void
NTAPI
SamOfflineLookupNamesInDomain(
							  _In_ SAM_HANDLE DomainHandle,
							  _In_ ULONG Count,
							  _In_reads_(Count) PCUNICODE_STRING Names,
							  _Out_ _Deref_post_count_(Count) PULONG *RelativeIds,
							  _Out_ _Deref_post_count_(Count) PSID_NAME_USE *Use
							  ){}

//////////////////////////////////////////////////////////////////////////
// Alias

NTSYSAPI
void
NTAPI
SamOfflineEnumerateAliasesInDomain(
								   _In_ SAM_HANDLE DomainHandle,
								   _Inout_ PSAM_ENUMERATE_HANDLE EnumerationContext,
								   _Outptr_ PSAM_RID_ENUMERATION *Buffer, 
								   _In_ ULONG PreferedMaximumLength,
								   _Out_ PULONG CountReturned
								   ){}

NTSYSAPI
void
NTAPI
SamOfflineCreateAliasInDomain(
							  _In_ SAM_HANDLE DomainHandle,
							  _In_ PCUNICODE_STRING AccountName,
							  _Out_ PSAM_HANDLE AliasHandle,
							  _Out_ PULONG RelativeId
							  ){}

NTSYSAPI
void
NTAPI
SamOfflineOpenAlias(
					_In_ SAM_HANDLE DomainHandle,
					_In_ ULONG AliasId,
					_Out_ PSAM_HANDLE AliasHandle
					){}

NTSYSAPI
void
NTAPI
SamOfflineAddMemberToAlias(
						   _In_ SAM_HANDLE AliasHandle,
						   _In_ PSID MemberId
						   ){}

NTSYSAPI
void
NTAPI
SamOfflineGetMembersInAlias(
							_In_ SAM_HANDLE AliasHandle,
							_Out_ _Deref_post_count_(*MemberCount) PSID **MemberIds,
							_Out_ PULONG MemberCount
							){}

NTSYSAPI
void
NTAPI
SamOfflineDeleteAlias(
					  _In_ SAM_HANDLE AliasHandle
					  ){}



NTSYSAPI
void
NTAPI
SamOfflineQueryInformationAlias(
								_In_ SAM_HANDLE AliasHandle,
								_In_ ALIAS_INFORMATION_CLASS AliasInformationClass,
								_Outptr_ PVOID *Buffer
								){}

NTSYSAPI
void
NTAPI
SamOfflineRemoveMemberFromAlias(
								_In_ SAM_HANDLE AliasHandle,
								_In_ PSID MemberId
								){}

NTSYSAPI
void
NTAPI
SamOfflineSetInformationAlias(
							  _In_ SAM_HANDLE AliasHandle,
							  _In_ ALIAS_INFORMATION_CLASS AliasInformationClass,
							  _In_ PVOID Buffer
							  ){}

//////////////////////////////////////////////////////////////////////////
// User

NTSYSAPI
void
NTAPI
SamOfflineCreateUserInDomain(
							 _In_ SAM_HANDLE DomainHandle,
							 _In_ PCUNICODE_STRING AccountName,
							 _Out_ PSAM_HANDLE UserHandle,
							 _Out_ PULONG RelativeId
							 ){}

NTSYSAPI
void
NTAPI
SamOfflineDeleteUser(
					 _In_ SAM_HANDLE UserHandle
					 ){}


NTSYSAPI
void
NTAPI
SamOfflineEnumerateUsersInDomain2(
								  _In_ SAM_HANDLE DomainHandle,
								  _Inout_ PSAM_ENUMERATE_HANDLE EnumerationContext,
								  _In_ ULONG UserAccountControl,
								  _Outptr_ PSAM_RID_ENUMERATION *Buffer, 
								  _In_ ULONG PreferedMaximumLength,
								  _Out_ PULONG CountReturned
								  ){}

NTSYSAPI
void
NTAPI
SamOfflineOpenUser(
				   _In_ SAM_HANDLE DomainHandle,
				   _In_ ULONG UserId,
				   _Out_ PSAM_HANDLE UserHandle
				   ){}

NTSYSAPI
void
NTAPI
SamOfflineQueryInformationUser(
							   _In_ SAM_HANDLE UserHandle,
							   _In_ USER_INFORMATION_CLASS UserInformationClass,
							   _Outptr_ PVOID *Buffer
							   ){}

NTSYSAPI
void
NTAPI
SamOfflineSetInformationUser(
							 _In_ SAM_HANDLE UserHandle,
							 _In_ USER_INFORMATION_CLASS UserInformationClass,
							 _In_ PVOID Buffer
							 ){}

EXTERN_C_END

