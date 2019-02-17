RevokeCert is a tool written in WinAPI/CryptoAPI to revoke, undo revoke, or dump certificates from PE or cert files.

The idea of RevokeCert is motivated by UAC denies the application to launch, if who's digital certificate is in the 'Disallowed' store.
RevokeCert also can process dual signatures if the OS API support SHA-256 certificates.

Usage: revokecert.exe <r|u|d|v> <PE or cert filename>
    r: revoke; u: undo revoke; d: dump to cert file beside input; v: view info
@lifenjoiner #20190217
Stop app to run needs UAC. https://en.wikipedia.org/wiki/User_Account_Control
OS < Windows NT 6.0 needs hotfix for SHA2, but without UAC.
KB968730: https://blogs.technet.microsoft.com/pki/2010/09/30/sha2-and-windows

p7b-dumper is a tool that dumps the Authenticode of PE file to a standalone file.

Others:
https://github.com/lifenjoiner/RevokeCert
