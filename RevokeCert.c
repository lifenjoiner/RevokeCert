// https://support.microsoft.com/en-us/help/323809/how-to-get-information-from-authenticode-signed-executables

#define _UNICODE
#define UNICODE

#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

BOOL PrintCertificateInfo(PCCERT_CONTEXT pCertContext);

TCHAR *_tcscat_x(TCHAR *path, TCHAR *ext_path) {
    path = realloc(path, (_tcslen(path) + _tcslen(ext_path)) * 2 + sizeof(TCHAR));
    return _tcscat(path, ext_path);
}

int _tmain(int argc, TCHAR *argv[]) {
    HCERTSTORE hStore = NULL, hSystemStore = NULL;
    HCRYPTMSG hMsg = NULL;
    PCCERT_CONTEXT pCertContext = NULL, pCertContext2 = NULL;
    BOOL fResult;
    DWORD dwEncoding, dwContentType, dwFormatType;
    PCMSG_SIGNER_INFO pSignerInfo = NULL;
    DWORD dwSignerInfo;
    CERT_INFO CertInfo;
    TCHAR *fname;

    __try {
        if (argc != 3) {
            _tprintf(_T("Usage: SignedFileInfo <r|u> <PE or cert filename>\n"));
            return 1;
        }

        //
        fname = argv[2];
        // Get message handle and store handle from the signed file.
        fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                                   fname,
                                   CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                                   CERT_QUERY_FORMAT_FLAG_BINARY,
                                   0,
                                   &dwEncoding,
                                   &dwContentType,
                                   &dwFormatType,
                                   &hStore,
                                   &hMsg,
                                   NULL);
        if (!fResult) {
            fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                                       fname,
                                       CERT_QUERY_CONTENT_FLAG_CERT,
                                       CERT_QUERY_FORMAT_FLAG_ALL,
                                       0,
                                       &dwEncoding,
                                       &dwContentType,
                                       &dwFormatType,
                                       &hStore,
                                       &hMsg,
                                       NULL);
        }
        if (!fResult) {
            _tprintf(_T("CryptQueryObject failed with %x\n"), GetLastError());
            __leave;
        }

        if (dwContentType == CERT_QUERY_CONTENT_CERT) {
            pCertContext = CertFindCertificateInStore(hStore,
                                                      ENCODING,
                                                      0,
                                                      CERT_FIND_ANY,
                                                      NULL,
                                                      NULL);
            if (!pCertContext) {
                _tprintf(_T("CertFindCertificateInStore failed with %x\n"),
                    GetLastError());
                __leave;
            }

            goto AceessByCertContext;
        }
        // Get signer information size.
        fResult = CryptMsgGetParam(hMsg,
                                   CMSG_SIGNER_INFO_PARAM,
                                   0,
                                   NULL,
                                   &dwSignerInfo);
        if (!fResult) {
            _tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
            __leave;
        }

        // Allocate memory for signer information.
        pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
        if (!pSignerInfo) {
            _tprintf(_T("Unable to allocate memory for Signer Info.\n"));
            __leave;
        }

        // Get Signer Information.
        fResult = CryptMsgGetParam(hMsg,
                                   CMSG_SIGNER_INFO_PARAM,
                                   0,
                                   (PVOID)pSignerInfo,
                                   &dwSignerInfo);
        if (!fResult) {
            _tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
            __leave;
        }

        // Search for the signer certificate in the temporary
        // certificate store.
        CertInfo.Issuer = pSignerInfo->Issuer;
        CertInfo.SerialNumber = pSignerInfo->SerialNumber;

        pCertContext = CertFindCertificateInStore(hStore,
                                                  ENCODING,
                                                  0,
                                                  CERT_FIND_SUBJECT_CERT,
                                                  (PVOID)&CertInfo,
                                                  NULL);
        if (!pCertContext) {
            _tprintf(_T("CertFindCertificateInStore failed with %x\n"),
                GetLastError());
            __leave;
        }

AceessByCertContext:
        //
        hSystemStore = CertOpenSystemStore(0, _T("Disallowed"));
        if (!hSystemStore) {
            _tprintf(_T("CertOpenSystemStore failed with %x\n"), GetLastError());
            __leave;
        }
        //
        PrintCertificateInfo(pCertContext);
        //
        if (!_tcsicmp(argv[1], _T("r"))) {
            // user's store
            fResult = CertAddCertificateContextToStore(hSystemStore,
                                                       pCertContext,
                                                       CERT_STORE_ADD_USE_EXISTING,
                                                       NULL);
            if (!fResult) {
                _tprintf(_T("CertAddCertificateContextToStore failed with %x\n"), GetLastError());
                __leave;
            }
        }
        else if (!_tcsicmp(argv[1], _T("u"))) {
            // user's store
            pCertContext2 = CertFindCertificateInStore(hSystemStore,
                                                       ENCODING,
                                                       0,
                                                       CERT_FIND_EXISTING,
                                                       pCertContext,
                                                       NULL);
            if (pCertContext2) {
                fResult = CertDeleteCertificateFromStore(pCertContext2);
                if (!fResult) {
                    _tprintf(_T("CertFindCertificateInStore failed with %x\n"), GetLastError());
                    __leave;
                }
            }
        }

    }
    __finally {
        // Clean up.
        if (pSignerInfo != NULL) LocalFree(pSignerInfo);
        if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
        if (hStore != NULL) CertCloseStore(hStore, 0);
        if (hMsg != NULL) CryptMsgClose(hMsg);
        if (hSystemStore != NULL) CertCloseStore(hSystemStore, 0);
    }
    return !fResult;
}

BOOL PrintCertificateInfo(PCCERT_CONTEXT pCertContext) {
    BOOL fReturn = FALSE;
    LPTSTR szName = NULL;
    DWORD dwData, n;

    __try {
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
            __leave;
        }

        // Allocate memory for Issuer name.
        szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
        if (!szName) {
            _tprintf(_T("Unable to allocate memory for issuer name.\n"));
            __leave;
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
            __leave;
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
            __leave;
        }

        // Allocate memory for subject name.
        szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
        if (!szName) {
            _tprintf(_T("Unable to allocate memory for subject name.\n"));
            __leave;
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
            __leave;
        }

        // Print Subject Name.
        _tprintf(_T("SubjectName: %s\n"), szName);

        fReturn = TRUE;
    }
    __finally {
        if (szName != NULL) LocalFree(szName);
    }

    return fReturn;
}
