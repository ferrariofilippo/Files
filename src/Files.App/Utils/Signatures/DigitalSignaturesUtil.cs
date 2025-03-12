// Copyright (c) Files Community
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using Windows.Win32.Foundation;
using static Files.App.Helpers.Win32PInvoke;

namespace Files.App.Utils.Signatures
{
	public static class DigitalSignaturesUtil
	{
		private const uint CMSG_SIGNER_INFO_PARAM = 6;

		private const uint PKCS_7_ASN_ENCODING = 0x00010000;
		private const uint CRYPT_ASN_ENCODING = 0x00000001;
		private const IntPtr PKCS7_SIGNER_INFO = 500;

		private const string SPC_SP_OPUS_INFO_OBJID = "1.3.6.1.4.1.311.2.1.12";

		public static List<SignatureInfoItem> GetSignaturesOfItem(string filePath)
		{
			var signatures = new List<SignatureInfoItem>();
			var pathPtr = Marshal.StringToHGlobalUni(filePath);
			var result = CryptQueryObject(
				(uint)CertQueryObjectType.CERT_QUERY_OBJECT_FILE,
				pathPtr,
				(uint)CertQueryContentFlags.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
				(uint)CertQueryFormatFlags.CERT_QUERY_FORMAT_FLAG_BINARY,
				0,
				out _,
				out _,
				out _,
				out IntPtr hStore,
				out IntPtr hMsg,
				out _
			);

			Marshal.FreeHGlobal(pathPtr);

			try
			{
				var index = 0u;
				while (result && GetSignerData(hMsg, index++, out var signature))
					signatures.Add(signature!);
			}
			finally
			{
				if (hStore != IntPtr.Zero)
					CertCloseStore(hStore, 0);

				if (hMsg != IntPtr.Zero)
					CryptMsgClose(hMsg);
			}

			return signatures;
		}

		// WIP
		private static bool GetSignerData(IntPtr hMsg, uint index, out SignatureInfoItem? signature)
		{
			signature = null;

			bool success = false;
			IntPtr pbSignerInfo = IntPtr.Zero;
			IntPtr pbEncodedSigner = IntPtr.Zero;

			var result = CryptMsgGetParam(
				hMsg,
				CMSG_SIGNER_INFO_PARAM,
				index,
				IntPtr.Zero,
				out var cbEncodedSigner
			);

			if (result)
			{
				pbEncodedSigner = Marshal.AllocHGlobal((int)cbEncodedSigner);
				result = CryptMsgGetParam(
					hMsg,
					CMSG_SIGNER_INFO_PARAM,
					index,
					pbEncodedSigner,
					out cbEncodedSigner
				);

				if (result)
				{
					// Error: CRYPT_E_ASN1_BADTAG ASN.1 bad tag value met 0x8009310B
					result = CryptDecodeObject(
						PKCS_7_ASN_ENCODING | CRYPT_ASN_ENCODING,
						PKCS7_SIGNER_INFO,
						pbEncodedSigner,
						cbEncodedSigner,
						0,
						IntPtr.Zero,
						out var sbSignerInfo
					);

					uint error = GetLastError();
					if (result)
					{
						pbSignerInfo = Marshal.AllocHGlobal((int)sbSignerInfo);
						result = CryptDecodeObject(
							PKCS_7_ASN_ENCODING | CRYPT_ASN_ENCODING,
							PKCS7_SIGNER_INFO,
							pbEncodedSigner,
							cbEncodedSigner,
							0,
							pbSignerInfo,
							out sbSignerInfo
						);

						//var pSignerData = Marshal.PtrToStructure<CMSG_SIGNER_INFO>(pbEncodedSigner);
						//var info = new Dictionary<string, string>();

						//result = GetProgramAndPublisherInfo(pSignerData, info);

						success = result;

						if (success)
							signature = new();

						Marshal.FreeHGlobal(pbSignerInfo);
					}
				}

				Marshal.FreeHGlobal(pbEncodedSigner);
			}

			return success;
		}

		// WIP
		private static bool GetProgramAndPublisherInfo(CMSG_SIGNER_INFO signerInfo, Dictionary<string, string> properties)
		{
			var result = false;
			var size = Marshal.SizeOf<CRYPT_ATTRIBUTE>();
			var attrCount = signerInfo.AuthAttrs.cbData / size;
			var objIdPtr = Marshal.StringToHGlobalUni(SPC_SP_OPUS_INFO_OBJID);
			var opusInfoPtr = IntPtr.Zero;

			for (int i = 0; i < attrCount; i++)
			{
				var currentAttrPtr = IntPtr.Add(signerInfo.AuthAttrs.pbData, i * size);
				var attr = Marshal.PtrToStructure<CRYPT_ATTRIBUTE>(currentAttrPtr);
				if (SPC_SP_OPUS_INFO_OBJID.Equals(attr.pszObjId))
				{
					var blob = Marshal.PtrToStructure<CRYPTOAPI_BLOB>(attr.rgValue);
					result = CryptDecodeObject(
						PKCS_7_ASN_ENCODING | CRYPT_ASN_ENCODING,
						objIdPtr,
						blob.pbData,
						blob.cbData,
						0,
						IntPtr.Zero,
						out var dwData
					);

					if (result)
					{
						opusInfoPtr = Marshal.AllocHGlobal((int)dwData);
						result = CryptDecodeObject(
							PKCS_7_ASN_ENCODING | CRYPT_ASN_ENCODING,
							objIdPtr,
							blob.pbData,
							blob.cbData,
							0,
							opusInfoPtr,
							out dwData
						);

						if (result)
						{
							var opusInfo = Marshal.PtrToStructure<SPC_SP_OPUS_INFO>(opusInfoPtr);
							if (opusInfo.pwszProgramName != IntPtr.Zero)
								properties["ProgramName"] = Marshal.PtrToStringUni(opusInfo.pwszProgramName) ?? string.Empty;

							if (opusInfo.pPublisherInfo != IntPtr.Zero)
							{
								//properties["PublisherLink"] =
							}

							if (opusInfo.pMoreInfo != IntPtr.Zero)
							{
								//properties["MoreInfoLink"] = 
							}
						}
					}
				}
			}

			if (opusInfoPtr != IntPtr.Zero)
				Marshal.FreeHGlobal(opusInfoPtr);

			Marshal.FreeHGlobal(objIdPtr);

			return result;
		}

		private static bool VerifySignature(string certPath)
		{
			var actionGuid = new Guid("{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}");
			var guidPtr = Marshal.AllocHGlobal(Marshal.SizeOf(actionGuid));
			Marshal.StructureToPtr(actionGuid, guidPtr, false);

			var sFileInfo = Marshal.SizeOf<WINTRUST_FILE_INFO>();
			var fileInfo = new WINTRUST_FILE_INFO
			{
				cbStruct = (uint)sFileInfo,
				pcwszFilePath = Marshal.StringToCoTaskMemAuto(certPath),
				hFile = IntPtr.Zero,
				pgKnownSubject = IntPtr.Zero
			};
			var filePtr = Marshal.AllocHGlobal(sFileInfo);
			Marshal.StructureToPtr(fileInfo, filePtr, false);

			var sData = Marshal.SizeOf<WINTRUST_DATA>();
			var wintrustData = new WINTRUST_DATA
			{
				cbStruct = (uint)sData,
				pPolicyCallbackData = IntPtr.Zero,
				pSIPClientData = IntPtr.Zero,
				dwUIChoice = 2,             // Display no UI
				fdwRevocationChecks = 0,    // No revocation checking
				dwUnionChoice = 1,          // Verify an embedded signature on a file
				dwStateAction = 1,          // Verify action
				hVWTStateData = HANDLE.Null,
				pwszURLReference = IntPtr.Zero,
				dwUIContext = 0,
				pFile = filePtr

			};
			var dataPtr = Marshal.AllocHGlobal(sData);
			Marshal.StructureToPtr(wintrustData, dataPtr, false);

			try
			{
				var res = WinVerifyTrust(IntPtr.Zero, guidPtr, dataPtr);

				// Release hWVTStateData
				wintrustData.dwStateAction = 2; // Close
				Marshal.StructureToPtr(wintrustData, dataPtr, true);
				WinVerifyTrust(IntPtr.Zero, guidPtr, dataPtr);

				return res == 0;
			}
			finally
			{
				if (fileInfo.pcwszFilePath != IntPtr.Zero)
					Marshal.FreeCoTaskMem(fileInfo.pcwszFilePath);

				Marshal.FreeHGlobal(guidPtr);
				Marshal.FreeHGlobal(filePtr);
				Marshal.FreeHGlobal(dataPtr);
			}
		}
	}
}
