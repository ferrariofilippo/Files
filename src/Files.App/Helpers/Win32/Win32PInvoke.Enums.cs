// Copyright (c) 2024 Files Community
// Licensed under the MIT License. See the LICENSE.

namespace Files.App.Helpers
{
	public static partial class Win32PInvoke
	{
		public enum RM_APP_TYPE
		{
			RmUnknownApp = 0,
			RmMainWindow = 1,
			RmOtherWindow = 2,
			RmService = 3,
			RmExplorer = 4,
			RmConsole = 5,
			RmCritical = 1000
		}

		public enum File_Attributes : uint
		{
			Readonly = 0x00000001,
			Hidden = 0x00000002,
			System = 0x00000004,
			Directory = 0x00000010,
			Archive = 0x00000020,
			Device = 0x00000040,
			Normal = 0x00000080,
			Temporary = 0x00000100,
			SparseFile = 0x00000200,
			ReparsePoint = 0x00000400,
			Compressed = 0x00000800,
			Offline = 0x00001000,
			NotContentIndexed = 0x00002000,
			Encrypted = 0x00004000,
			Write_Through = 0x80000000,
			Overlapped = 0x40000000,
			NoBuffering = 0x20000000,
			RandomAccess = 0x10000000,
			SequentialScan = 0x08000000,
			DeleteOnClose = 0x04000000,
			BackupSemantics = 0x02000000,
			PosixSemantics = 0x01000000,
			OpenReparsePoint = 0x00200000,
			OpenNoRecall = 0x00100000,
			FirstPipeInstance = 0x00080000
		}

		public enum FILE_INFO_BY_HANDLE_CLASS
		{
			FileBasicInfo = 0,
			FileStandardInfo = 1,
			FileNameInfo = 2,
			FileRenameInfo = 3,
			FileDispositionInfo = 4,
			FileAllocationInfo = 5,
			FileEndOfFileInfo = 6,
			FileStreamInfo = 7,
			FileCompressionInfo = 8,
			FileAttributeTagInfo = 9,
			FileIdBothDirectoryInfo = 10,// 0x0A
			FileIdBothDirectoryRestartInfo = 11, // 0xB
			FileIoPriorityHintInfo = 12, // 0xC
			FileRemoteProtocolInfo = 13, // 0xD
			FileFullDirectoryInfo = 14, // 0xE
			FileFullDirectoryRestartInfo = 15, // 0xF
			FileStorageInfo = 16, // 0x10
			FileAlignmentInfo = 17, // 0x11
			FileIdInfo = 18, // 0x12
			FileIdExtdDirectoryInfo = 19, // 0x13
			FileIdExtdDirectoryRestartInfo = 20, // 0x14
			MaximumFileInfoByHandlesClass
		}

		public enum GET_FILEEX_INFO_LEVELS
		{
			GetFileExInfoStandard,
		}

		public enum StreamInfoLevels
		{
			FindStreamInfoStandard = 0
		}

		[Flags]
		public enum CryptProtectFlags
		{
			CRYPTPROTECT_UI_FORBIDDEN = 0x1,
			CRYPTPROTECT_LOCAL_MACHINE = 0x4,
			CRYPTPROTECT_CRED_SYNC = 0x8,
			CRYPTPROTECT_AUDIT = 0x10,
			CRYPTPROTECT_NO_RECOVERY = 0x20,
			CRYPTPROTECT_VERIFY_PROTECTION = 0x40,
			CRYPTPROTECT_CRED_REGENERATE = 0x80
		}

		public enum TOKEN_INFORMATION_CLASS
		{
			TokenUser = 1,
			TokenGroups,
			TokenPrivileges,
			TokenOwner,
			TokenPrimaryGroup,
			TokenDefaultDacl,
			TokenSource,
			TokenType,
			TokenImpersonationLevel,
			TokenStatistics,
			TokenRestrictedSids,
			TokenSessionId,
			TokenGroupsAndPrivileges,
			TokenSessionReference,
			TokenSandBoxInert,
			TokenAuditPolicy,
			TokenOrigin,
			TokenElevationType,
			TokenLinkedToken,
			TokenElevation,
			TokenHasRestrictions,
			TokenAccessInformation,
			TokenVirtualizationAllowed,
			TokenVirtualizationEnabled,
			TokenIntegrityLevel,
			TokenUIAccess,
			TokenMandatoryPolicy,
			TokenLogonSid,
			TokenIsAppContainer,
			TokenCapabilities,
			TokenAppContainerSid,
			TokenAppContainerNumber,
			TokenUserClaimAttributes,
			TokenDeviceClaimAttributes,
			TokenRestrictedUserClaimAttributes,
			TokenRestrictedDeviceClaimAttributes,
			TokenDeviceGroups,
			TokenRestrictedDeviceGroups,
			TokenSecurityAttributes,
			TokenIsRestricted
		}

		[Serializable]
		public enum TOKEN_TYPE
		{
			TokenPrimary = 1,
			TokenImpersonation = 2
		}

		[Flags]
		public enum TokenAccess : uint
		{
			TOKEN_ASSIGN_PRIMARY = 0x0001,
			TOKEN_DUPLICATE = 0x0002,
			TOKEN_IMPERSONATE = 0x0004,
			TOKEN_QUERY = 0x0008,
			TOKEN_QUERY_SOURCE = 0x0010,
			TOKEN_ADJUST_PRIVILEGES = 0x0020,
			TOKEN_ADJUST_GROUPS = 0x0040,
			TOKEN_ADJUST_DEFAULT = 0x0080,
			TOKEN_ADJUST_SESSIONID = 0x0100,
			TOKEN_ALL_ACCESS_P = 0x000F00FF,
			TOKEN_ALL_ACCESS = 0x000F01FF,
			TOKEN_READ = 0x00020008,
			TOKEN_WRITE = 0x000200E0,
			TOKEN_EXECUTE = 0x00020000
		}

		public enum FINDEX_INFO_LEVELS
		{
			FindExInfoStandard = 0,
			FindExInfoBasic = 1
		}

		public enum FINDEX_SEARCH_OPS
		{
			FindExSearchNameMatch = 0,
			FindExSearchLimitToDirectories = 1,
			FindExSearchLimitToDevices = 2
		}

		[Flags]
		public enum ClassContext : uint
		{
			LocalServer = 0x4
		}

		public enum CertQueryObjectType : uint
		{
			CERT_QUERY_OBJECT_FILE = 0x00000001,
			CERT_QUERY_OBJECT_BLOB = 0x00000002,
		}

		public enum CertQueryFormatType : uint
		{
			CERT_QUERY_FORMAT_BINARY = 1,
			CERT_QUERY_FORMAT_BASE64_ENCODED = 2,
			CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED = 3,
		}

		[Flags]
		public enum CertQueryFormatFlags : uint
		{
			CERT_QUERY_FORMAT_FLAG_BINARY = (1u << (int)CertQueryFormatType.CERT_QUERY_FORMAT_BINARY),
			CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED = (1u << (int)CertQueryFormatType.CERT_QUERY_FORMAT_BASE64_ENCODED),
			CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED = (1u << (int)CertQueryFormatType.CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED),
			CERT_QUERY_FORMAT_FLAG_ALL = (CERT_QUERY_FORMAT_FLAG_BINARY | CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED | CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED),
		}

		public enum CertQueryContentType : uint
		{
			CERT_QUERY_CONTENT_CERT = 1,
			CERT_QUERY_CONTENT_CTL = 2,
			CERT_QUERY_CONTENT_CRL = 3,
			CERT_QUERY_CONTENT_SERIALIZED_STORE = 4,
			CERT_QUERY_CONTENT_SERIALIZED_CERT = 5,
			CERT_QUERY_CONTENT_SERIALIZED_CTL = 6,
			CERT_QUERY_CONTENT_SERIALIZED_CRL = 7,
			CERT_QUERY_CONTENT_PKCS7_SIGNED = 8,
			CERT_QUERY_CONTENT_PKCS7_UNSIGNED = 9,
			CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED = 10,
			CERT_QUERY_CONTENT_PKCS10 = 11,
			CERT_QUERY_CONTENT_PFX = 12,
			CERT_QUERY_CONTENT_CERT_PAIR = 13,
			CERT_QUERY_CONTENT_PFX_AND_LOAD = 14,
		}

		[Flags]
		public enum CertQueryContentFlags : uint
		{
			CERT_QUERY_CONTENT_FLAG_ALL = (CERT_QUERY_CONTENT_FLAG_CERT | CERT_QUERY_CONTENT_FLAG_CTL | CERT_QUERY_CONTENT_FLAG_CRL | CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE | CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT | CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL | CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS10 | CERT_QUERY_CONTENT_FLAG_PFX | CERT_QUERY_CONTENT_FLAG_CERT_PAIR),
			CERT_QUERY_CONTENT_FLAG_ALL_ISSUER_CERT = (CERT_QUERY_CONTENT_FLAG_CERT | CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE | CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED),
			CERT_QUERY_CONTENT_FLAG_CERT = (1u << (int)CertQueryContentType.CERT_QUERY_CONTENT_CERT),
			CERT_QUERY_CONTENT_FLAG_CERT_PAIR = (1u << (int)CertQueryContentType.CERT_QUERY_CONTENT_CERT_PAIR),
			CERT_QUERY_CONTENT_FLAG_CRL = (1u << (int)CertQueryContentType.CERT_QUERY_CONTENT_CRL),
			CERT_QUERY_CONTENT_FLAG_CTL = (1u << (int)CertQueryContentType.CERT_QUERY_CONTENT_CTL),
			CERT_QUERY_CONTENT_FLAG_PFX = (1u << (int)CertQueryContentType.CERT_QUERY_CONTENT_PFX),
			CERT_QUERY_CONTENT_FLAG_PFX_AND_LOAD = (1u << (int)CertQueryContentType.CERT_QUERY_CONTENT_PFX_AND_LOAD),
			CERT_QUERY_CONTENT_FLAG_PKCS10 = (1u << (int)CertQueryContentType.CERT_QUERY_CONTENT_PKCS10),
			CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED = (1u << (int)CertQueryContentType.CERT_QUERY_CONTENT_PKCS7_SIGNED),
			CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = (1u << (int)CertQueryContentType.CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED),
			CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED = (1u << (int)CertQueryContentType.CERT_QUERY_CONTENT_PKCS7_UNSIGNED),
			CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT = (1u << (int)CertQueryContentType.CERT_QUERY_CONTENT_SERIALIZED_CERT),
			CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL = (1u << (int)CertQueryContentType.CERT_QUERY_CONTENT_SERIALIZED_CRL),
			CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL = (1u << (int)CertQueryContentType.CERT_QUERY_CONTENT_SERIALIZED_CTL),
			CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE = (1u << (int)CertQueryContentType.CERT_QUERY_CONTENT_SERIALIZED_STORE),
		}
	}
}
