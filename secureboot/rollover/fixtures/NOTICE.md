# Fixture Sources

Every file in this folder except NOTICE.md is an unmodified copy from [microsoft/secureboot_objects](https://github.com/microsoft/secureboot_objects) at commit 3d762aecbaecd12402efd21ba89c8c7bd40da4bd, used under the BSD-2-Clause-Patent license reproduced in [License.txt](License.txt). Copyright (C) Microsoft Corporation.

| File | Source path |
|---|---|
| MicCorKEKCA2011_2011-06-24.der | PreSignedObjects/KEK/Certificates/MicCorKEKCA2011_2011-06-24.der |
| microsoft corporation kek 2k ca 2023.der | PreSignedObjects/KEK/Certificates/microsoft corporation kek 2k ca 2023.der |
| MicWinProPCA2011_2011-10-19.der | PreSignedObjects/DB/Certificates/MicWinProPCA2011_2011-10-19.der |
| MicCorUEFCA2011_2011-06-27.der | PreSignedObjects/DB/Certificates/MicCorUEFCA2011_2011-06-27.der |
| windows uefi ca 2023.der | PreSignedObjects/DB/Certificates/windows uefi ca 2023.der |
| microsoft uefi ca 2023.der | PreSignedObjects/DB/Certificates/microsoft uefi ca 2023.der |
| microsoft option rom uefi ca 2023.der | PreSignedObjects/DB/Certificates/microsoft option rom uefi ca 2023.der |
| dbx_info_msft_latest.json | PreSignedObjects/DBX/dbx_info_msft_latest.json |
| DBXUpdate.bin | PostSignedObjects/DBX/amd64/DBXUpdate.bin |
| DBUpdate2024.bin | PostSignedObjects/Optional/DB/DBUpdate2024.bin |
| DBUpdate3P2023.bin | PostSignedObjects/Optional/DB/DBUpdate3P2023.bin |
| DBUpdateOROM2023.bin | PostSignedObjects/Optional/DB/DBUpdateOROM2023.bin |
| DBXUpdateSVN.bin | PostSignedObjects/Optional/DBX/DBXUpdateSVN.bin |
| dbx_x64.efiauth2 | PostSignedObjects/SignedByKEK2023/dbx_x64.efiauth2 |
| dbx_SVN.efiauth2 | PostSignedObjects/SignedByKEK2023/dbx_SVN.efiauth2 |
| License.txt | License.txt |

These files are test inputs only. Do not apply the update packages to a device with this tool; it cannot write UEFI variables. Microsoft warns that applying DBXUpdateSVN.bin or the 2024 dbx update without first adding Windows UEFI CA 2023 to db leaves Windows unbootable.
