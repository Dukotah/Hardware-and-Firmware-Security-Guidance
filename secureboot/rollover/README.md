# Secure Boot 2023 CA Rollover Check

sbrollover.py is a read-only checker for the Microsoft 2011 to 2023 Secure Boot certificate rollover. It reads exported PK, KEK, db, and dbx contents and reports:

- Which Microsoft certificates are present, identified by SHA-1 thumbprint, and whether they have expired:
  - Microsoft Corporation KEK CA 2011 and Microsoft Corporation KEK 2K CA 2023 (KEK)
  - Microsoft Windows Production PCA 2011, Microsoft Corporation UEFI CA 2011, Windows UEFI CA 2023, Microsoft UEFI CA 2023, and Microsoft Option ROM UEFI CA 2023 (db)
- Which certificates signed an authenticated update file (for example, whether a dbx update was signed under the 2011 or the 2023 KEK).
- The dbx revocation status: whether Microsoft Windows Production PCA 2011 is revoked (the final CVE-2023-24932 mitigation), the boot manager Security Version Number (SVN) entries, and, given Microsoft's dbx reference JSON, how many known revoked image hashes are present.
- Findings marked OK, INFO, WARN, or ACTION. The exit code is 1 if any ACTION finding is reported, so the tool can be used in scripts.

It needs Python 3.9 or later and uses only the standard library. It never writes UEFI variables.

## Inputs
Each of --pk, --kek, --db, and --dbx accepts any of the following, detected automatically:

- Raw EFI signature lists, such as files written by `Get-SecureBootUEFI -Name db -OutputFilePath db.esl` on Windows (section 2.7 of [Windows.md](../Windows.md)) or `efi-readvar -v db -o db.esl` on Linux (section 2.8 of [Linux.md](../Linux.md)).
- Linux efivarfs files, which start with a 4-byte attribute field, such as /sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f. Use --efivars to read all four variables from efivarfs at once.
- Authenticated variable updates (EFI_VARIABLE_AUTHENTICATION_2), such as Microsoft's DBXUpdate.bin and .efiauth2 files.

## Examples
Check the local Linux system (efivarfs is readable by root):
```
sudo python3 sbrollover.py --efivars --dbx-reference fixtures/dbx_info_msft_latest.json --arch x64
```
Check values exported on Windows with Get-SecureBootUEFI (run from an elevated PowerShell prompt):
```
python sbrollover.py --kek KEK.esl --db DB.esl --dbx DBX.esl --dbx-reference fixtures/dbx_info_msft_latest.json --arch x64
```
Inspect a Microsoft update package before applying it:
```
$ python3 sbrollover.py --db fixtures/DBUpdate2024.bin
== db (auth2)
   signed by: Microsoft Windows UEFI Key Exchange Key (issuer Microsoft Corporation KEK CA 2011, expires 2024-01-31)
   signed by: Microsoft Corporation KEK CA 2011 (issuer Microsoft Corporation Third Party Marketplace Root, expires 2026-06-24)
   X509   Windows UEFI CA 2023  [Windows UEFI CA 2023]  sha1=45a0fa32604773c82433c3b7d59e7466b3ac0c67  notAfter=2035-06-13
== findings
   [OK] db trusts Windows UEFI CA 2023: boot managers signed by the 2023 CA will boot.
```
Add --json for machine-readable output.

## Tests
```
python3 test_sbrollover.py -v
```
The tests use Microsoft's published certificates, signed update packages, and dbx reference data as fixtures. See [fixtures/NOTICE.md](fixtures/NOTICE.md) for their source and license.

## References
- Microsoft, [Windows Secure Boot certificate expiration and CA updates](https://support.microsoft.com/topic/windows-secure-boot-certificate-expiration-and-ca-updates-7ff40d33-95dc-4c3c-8725-a9b95457578e)
- Microsoft, [KB5025885: How to manage the Windows Boot Manager revocations for Secure Boot changes associated with CVE-2023-24932](https://support.microsoft.com/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d)
- Microsoft, [secureboot_objects](https://github.com/microsoft/secureboot_objects)
- UEFI Forum, [UEFI Specification 2.10](https://uefi.org/specs/UEFI/2.10/), section 32.4.1 (Signature Database) and section 8.2.2 (EFI_VARIABLE_AUTHENTICATION_2)
