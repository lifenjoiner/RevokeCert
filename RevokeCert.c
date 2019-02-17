/* Intro
RevokeCert is a tool written in WinAPI to revoke, undo revoke, or dump certificates from PE or cert files.
*/

/* References
https://support.microsoft.com/en-us/help/323809/how-to-get-information-from-authenticode-signed-executables
szOID_NESTED_SIGNATURE:
https://stackoverflow.com/questions/36931928/how-to-retrieve-information-from-multiple-dual-code-signatures-on-an-executable
UAC
https://en.wikipedia.org/wiki/User_Account_Control
*/

#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include <locale.h>
#include <mbctype.h>
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

#ifndef szOID_NESTED_SIGNATURE
#define szOID_NESTED_SIGNATURE "1.3.6.1.4.1.311.2.4.1"
#endif

TCHAR *_tcscat_x(TCHAR *path, TCHAR *ext_path) {
    path = realloc(path, (_tcslen(path) + _tcslen(ext_path)) * 2 + sizeof(TCHAR));
    return _tcscat(path, ext_path);
}

BOOL PrintCertificateInfo(PCCERT_CONTEXT pCertContext) {
    BOOL fReturn = FALSE;
    LPTSTR szName = NULL;
    DWORD dwData, n;

    // Print Serial Number.
    _tprintf(_T("SerialNumber: "));
    dwData = pCertContext->pCertInfo->SerialNumber.cbData;
    for (n = 0; n < dwData; n++) {
        _tprintf(_T("%02x"),
          pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
    }
    _tprintf(_T("\n"));

    // Get Issuer name size.
    if (!(dwData = CertGetNameString(pCertContext,
                                     CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                     CERT_NAME_ISSUER_FLAG,
                                     NULL,
                                     NULL,
                                     0)))
    {
        _tprintf(_T("CertGetNameString failed.\n"));
        goto leave;
    }

    // Allocate memory for Issuer name.
    szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
    if (!szName) {
        _tprintf(_T("Unable to allocate memory for issuer name.\n"));
        goto leave;
    }

    // Get Issuer name.
    if (!(CertGetNameString(pCertContext,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            CERT_NAME_ISSUER_FLAG,
                            NULL,
                            szName,
                            dwData)))
    {
        _tprintf(_T("CertGetNameString failed.\n"));
        goto leave;
    }

    // print Issuer name.
    _tprintf(_T("IssuerName: %s\n"), szName);
    LocalFree(szName);
    szName = NULL;

    // Get Subject name size.
    if (!(dwData = CertGetNameString(pCertContext,
                                     CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                     0,
                                     NULL,
                                     NULL,
                                     0)))
    {
        _tprintf(_T("CertGetNameString failed.\n"));
        goto leave;
    }

    // Allocate memory for subject name.
    szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
    if (!szName) {
        _tprintf(_T("Unable to allocate memory for subject name.\n"));
        goto leave;
    }

    // Get subject name.
    if (!(CertGetNameString(pCertContext,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0,
                            NULL,
                            szName,
                            dwData)))
    {
        _tprintf(_T("CertGetNameString failed.\n"));
        goto leave;
    }

    // Print Subject Name.
    _tprintf(_T("SubjectName: %s\n"), szName);

    fReturn = TRUE;

leave:
    if (szName != NULL) LocalFree(szName);

    return fReturn;
}

BOOL DumpBuffToFile(TCHAR *fname, BYTE *Buff, DWORD BuffLen) {
    FILE *fp_w = NULL;
    //
    fp_w = _tfopen(fname, _T("w+b"));
    if (fp_w == NULL) {
        _tprintf(_T("Failed: create output file.\n"));
        return FALSE;
    }
    fwrite(Buff, 1, BuffLen, fp_w);
    fflush(fp_w);
    if (fp_w) fclose(fp_w);
    return TRUE;
}

BOOL GetSignerInfoFromMsg(HCRYPTMSG hMsg, PCMSG_SIGNER_INFO *ppSignerInfo) {
    DWORD dwSignerInfo;
    BOOL fResult;

    // Get signer information size.
    fResult = CryptMsgGetParam(hMsg,
                               CMSG_SIGNER_INFO_PARAM,
                               0,
                               NULL,
                               &dwSignerInfo);
    if (!fResult) {
        _tprintf(_T("CryptMsgGetParam failed with 0x%08x\n"), GetLastError());
        return FALSE;
    }

    // Allocate memory for signer information.
    *ppSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
    if (!*ppSignerInfo) {
        _tprintf(_T("Unable to allocate memory for Signer Info.\n"));
        return FALSE;
    }

    // Get Signer Information.
    fResult = CryptMsgGetParam(hMsg,
                               CMSG_SIGNER_INFO_PARAM,
                               0,
                               (PVOID)*ppSignerInfo,
                               &dwSignerInfo);
    if (!fResult) {
        _tprintf(_T("CryptMsgGetParam failed with 0x%08x\n"), GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL GetCertContextInStoreBySignerInfo(PCCERT_CONTEXT *ppCertContext, HCERTSTORE hStore, PCMSG_SIGNER_INFO pSignerInfo) {
    CERT_INFO CertInfo;
    BOOL fResult;

    // Search for the signer certificate in the temporary certificate store.
    CertInfo.Issuer = pSignerInfo->Issuer;
    CertInfo.SerialNumber = pSignerInfo->SerialNumber;

    *ppCertContext = CertFindCertificateInStore(hStore,
                                              ENCODING,
                                              0,
                                              CERT_FIND_SUBJECT_CERT,
                                              (PVOID)&CertInfo,
                                              NULL);
    if (!*ppCertContext) {
        _tprintf(_T("CertFindCertificateInStore failed with 0x%08x\n"), GetLastError());
        fResult = FALSE;
    }
    else {
        fResult = TRUE;
    }

    return fResult;
}

BOOL AddCertToDisallowedByCertContext(PCCERT_CONTEXT pCertContext) {
    HCERTSTORE hStore = NULL;
    BOOL fResult;

    hStore = CertOpenSystemStore(0, _T("Disallowed"));
    if (!hStore) {
        _tprintf(_T("CertOpenSystemStore failed with 0x%08x\n"), GetLastError());
        return FALSE;
    }
    // user's store
    fResult = CertAddCertificateContextToStore(hStore,
                                               pCertContext,
                                               CERT_STORE_ADD_USE_EXISTING,
                                               NULL);
    if (!fResult) {
        _tprintf(_T("CertAddCertificateContextToStore failed with 0x%08x\n"), GetLastError());
    }

    if (hStore != NULL) CertCloseStore(hStore, 0);
    return fResult;
}

BOOL DelCertInDisallowedByCertContext(PCCERT_CONTEXT pCertContext) {
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCertContext2;
    BOOL fResult;

    hStore = CertOpenSystemStore(0, _T("Disallowed"));
    if (!hStore) {
        _tprintf(_T("CertOpenSystemStore failed with 0x%08x\n"), GetLastError());
        return FALSE;
    }
    // user's store
    pCertContext2 = CertFindCertificateInStore(hStore,
                                               ENCODING,
                                               0,
                                               CERT_FIND_EXISTING,
                                               pCertContext,
                                               NULL);
    if (pCertContext2) {
        fResult = CertDeleteCertificateFromStore(pCertContext2);
        if (!fResult) {
            _tprintf(_T("DeleteCertificateFromStore failed with 0x%08x\n"), GetLastError());
        }
    }

    if (pCertContext2 != NULL) CertFreeCertificateContext(pCertContext2);
    if (hStore != NULL) CertCloseStore(hStore, 0);

    return fResult;
}

enum _PROCESS_ACTION {
    REVOKE = 1,
    UNREVOKE,
    DUMP
};

int CertCounter = 0;

BOOL ProcessByCertContext(PCCERT_CONTEXT pCertContext, int action, TCHAR *fname) {
    BOOL ret;
    TCHAR *fname_der;
    TCHAR fname_idx[4] = _T("");

    PrintCertificateInfo(pCertContext);
    //
    switch (action) {
    case REVOKE:
        ret = AddCertToDisallowedByCertContext(pCertContext);
        _tprintf(_T("Added\n"));
        break;
    case UNREVOKE:
        ret = DelCertInDisallowedByCertContext(pCertContext);
        _tprintf(_T("Deleted\n"));
        break;
    case DUMP:
        fname_der = _tcsdup(fname);
        CertCounter++;
        _sntprintf(fname_idx, sizeof(fname_idx), _T(".%02d"), CertCounter);
        fname_der = _tcscat_x(fname_der, fname_idx);
        fname_der = _tcscat_x(fname_der, _T(".der"));
        //
        ret = DumpBuffToFile(fname_der, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
        _tprintf(_T("Dumped: %s\n"), fname_der);
        break;
    default:
        ret = TRUE;
    };

    return ret;
}

BOOL ProcessNestedSignedData(PCMSG_SIGNER_INFO pSignerInfoPre, int action, TCHAR *fname) {
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fResult;
    DWORD dwEncoding, dwContentType, dwFormatType;
    PCMSG_SIGNER_INFO pSignerInfo = NULL;
    DWORD i;

    for (i = 0; i < pSignerInfoPre->UnauthAttrs.cAttr; i++) {
        if (lstrcmpA(pSignerInfoPre->UnauthAttrs.rgAttr[i].pszObjId, szOID_NESTED_SIGNATURE) == 0)
            break; // <-- Only one signer!
    }
    if (i >= pSignerInfoPre->UnauthAttrs.cAttr) goto leave;
    // Get message handle and store handle from the signed file.
    // Failed on XP!? XP does NOT support the new SHA2 standard. Can't decode.
    // https://social.msdn.microsoft.com/Forums/windowsdesktop/en-US/40dcf50b-c637-4d7d-b0c0-598a61f96f8c/rfc3161-timestamp-information-in-digital-signature-authenticode?forum=windowsgeneraldevelopmentissues
    // https://blogs.technet.microsoft.com/pki/2010/09/30/sha2-and-windows/
    fResult = CryptQueryObject(CERT_QUERY_OBJECT_BLOB,
                               pSignerInfoPre->UnauthAttrs.rgAttr[i].rgValue,
                               CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                               CERT_QUERY_FORMAT_FLAG_BINARY,
                               0,
                               &dwEncoding,
                               &dwContentType,
                               &dwFormatType,
                               &hStore,
                               &hMsg,
                               NULL);
    if (!fResult) {
        _tprintf(_T("CryptQueryObject failed with 0x%08x on nested SignedData\n"), GetLastError());
        goto leave;
    }

    // Get signer information
    fResult = GetSignerInfoFromMsg(hMsg, &pSignerInfo);
    if (!fResult) goto leave;

    //
    fResult = GetCertContextInStoreBySignerInfo(&pCertContext, hStore, pSignerInfo);
    if (!fResult) goto leave;

    //
    _tprintf(_T("\n"));
    fResult = ProcessByCertContext(pCertContext, action, fname);

    // The next nested one!
    fResult = ProcessNestedSignedData(pSignerInfo, action, fname);

leave:
    if (hMsg != NULL) CryptMsgClose(hMsg);
    if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
    if (hStore != NULL) CertCloseStore(hStore, 0);
    if (pSignerInfo != NULL) LocalFree(pSignerInfo);

    return !fResult;
}

int _tmain(int argc, TCHAR *argv[]) {
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fResult;
    DWORD dwEncoding, dwContentType, dwFormatType;
    PCMSG_SIGNER_INFO pSignerInfo = NULL;
    DWORD i;

    int action;
    size_t n;
    TCHAR *fname;
    WCHAR *fname_w;

    BYTE *pbCertEncoded;

    TCHAR MBCP[8] = _T("");
    int CP;

    if (argc != 3) {
        _tprintf(_T("Usage: %s <r|u|d|v> <PE or cert filename>\n"), argv[0]);
        _tprintf(_T("    r: revoke; u: undo revoke; d: dump to cert file beside input; v: view info\n"));
        _tprintf(_T("@lifenjoiner #20190217\n"));
        _tprintf(_T("Stop app to run needs UAC. https://en.wikipedia.org/wiki/User_Account_Control\n"));
        _tprintf(_T("OS < Windows NT 6.0 needs hotfix for SHA2\n"));
        _tprintf(_T("KB968730: https://blogs.technet.microsoft.com/pki/2010/09/30/sha2-and-windows\n"));
        return 1;
    }

    if (!_tcsicmp(argv[1], _T("d"))) { action = DUMP; }
    else if (!_tcsicmp(argv[1], _T("r"))) { action = REVOKE; }
    else if (!_tcsicmp(argv[1], _T("u"))) { action = UNREVOKE; }
    //
    fname = argv[2];

    //
    CP = _getmbcp(); /* Consider it's different from default. */
    if (CP > 0) _sntprintf(MBCP, sizeof(MBCP), _T(".%d"), CP);
    _tsetlocale(LC_ALL, MBCP);

#ifdef UNICODE
    fname_w = _tcsdup(fname);
#else
    n = 2 * (strlen(fname) + 1);
    fname_w = malloc(n);
    if (mbstowcs(fname_w, fname, n) == -1) {
        printf("Unable to convert to unicode.\n");
        goto leave;
    }
#endif

    // try cert file
    fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                               fname_w,
                               CERT_QUERY_CONTENT_FLAG_CERT,
                               CERT_QUERY_FORMAT_FLAG_ALL,
                               0,
                               &dwEncoding,
                               &dwContentType,
                               &dwFormatType,
                               &hStore,
                               &hMsg,
                               (const void**)&pCertContext);
    if (fResult && dwContentType == CERT_QUERY_CONTENT_CERT && pCertContext) {
        fResult = ProcessByCertContext(pCertContext, action, fname);
        goto leave;
    }

    // Get message handle and store handle from the signed file.
    fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                               fname_w,
                               CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED|CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                               CERT_QUERY_FORMAT_FLAG_BINARY,
                               0,
                               &dwEncoding,
                               &dwContentType,
                               &dwFormatType,
                               &hStore,
                               &hMsg,
                               NULL);
    if (!fResult) {
        _tprintf(_T("CryptQueryObject failed with 0x%08x\n"), GetLastError());
        goto leave;
    }

    // Get signer information size.
    fResult = GetSignerInfoFromMsg(hMsg, &pSignerInfo);
    if (!fResult) goto leave;

    //
    fResult = GetCertContextInStoreBySignerInfo(&pCertContext, hStore, pSignerInfo);
    if (!fResult) goto leave;

    //
    fResult = ProcessByCertContext(pCertContext, action, fname);

    // NESTED SIGNATURE in CMSG_SIGNER_INFO.UnauthAttrs, multiple/dual code signatures
    fResult = ProcessNestedSignedData(pSignerInfo, action, fname);

leave:
    if (hMsg != NULL) CryptMsgClose(hMsg);
    if (pSignerInfo != NULL) LocalFree(pSignerInfo);
    if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
    if (hStore != NULL) CertCloseStore(hStore, 0);

    return !fResult;
}
