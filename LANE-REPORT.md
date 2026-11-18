# LANE 6 report: Hardware-and-Firmware-Security-Guidance

## 1. Upstream contribution rules (CONTRIBUTING.md)

- The only rule is the copyright waiver: contributions are released under CC0 1.0. US government employees' changes are public domain in the US; everyone else's are CC0 in the US and worldwide.
- Opening a pull request means agreeing to that waiver.
- There is no style guide, test requirement, or issue-first rule. In practice only one PR has ever merged (#19, a typo fix, 2021), and the maintainer edits README.md directly, so this lane keeps the upstream PR small and docs-only.

## 2. Branches

| Branch | Base | Bound for | Commits |
|---|---|---|---|
| `fix/secureboot-docs` | upstream/master `f87939e` | upstream PR (Fixes #24, #25, #26) | `ea4ed61` Fix Secure Boot signing snippets and add Fedora/SDK-free options |
| `lane/secureboot-2023-rollover` | `fix/secureboot-docs` | fork only | rollover checker + CI, this report |

### A: `fix/secureboot-docs` (2 files, +29/-11)
`secureboot/Windows.md`
- Section 2.4 hash snippet, line 65: `$hashString,Substring` is now `$hashString.Substring`. This was a parse error, and nobody had filed it.
- Same snippet, a second bug found while testing: with the comma fixed, the loop still threw `Could not find any recognizable digits`. `$hashString.Trim("0x")` only wrote the trimmed value to the TXT file, so the loop still converted the `0x` prefix. `Trim("0x")` also strips leading and trailing `0` digits from the hash. It is now `$hashString = $hashString -replace '^0x', ''`.
- Line 67 (`set-content -encoding byte`, which fails on PowerShell 7) is left alone because open PR #22 changes exactly that line.
- Section 2.1 (#24): makecert is not built into Windows. It is in the Bin folder of the Windows SDK and is deprecated, with links to Microsoft's docs. The section now has a `New-SelfSignedCertificate` alternative that exports DER `.cer` files and password-protected `.pfx` files, then deletes the certificate and key from `Cert:\CurrentUser\My`.

`secureboot/Linux.md`
- Section 2.4 and recipe 1.1 (#26): kmodsign is Ubuntu-only (package sbsigntool). Added the Fedora/RHEL equivalent, `/usr/src/kernels/$(uname -r)/scripts/sign-file` from kernel-devel, which takes the same arguments, with a link to docs.kernel.org module-signing. Added a comment to the McAfee example script.
- Sections 2.3 and 2.9 (#25): I reproduced the reporter's exact error. `pesign: Error opening input: No such file or directory` happens when shimx64.efi is not in the working directory, not because of the `-i=` syntax (pesign 116 accepts `-i=`). The text now says to copy Shim from the EFI System Partition (`/boot/efi/EFI/fedora/shimx64.efi` on Fedora, checked against the shim-x64 file list). It also uses `-i shimx64.efi`, matching section 2.5.
- Sections 2.3 and 2.10, a bug found while testing: `pesign -r -i=shimx64.efi -o=shimx64.efi` never worked. pesign prints `in-place file editing is not yet supported` and, without `-u`, `Invalid signature number -1`. Both still exit 0. The commands are now `pesign -r -u 0 -i shimx64.efi -o shimx64-nosig.efi` followed by `mv`.

### B: `lane/secureboot-2023-rollover` (fork only)
`secureboot/rollover/sbrollover.py` is a read-only checker for the Microsoft 2011 to 2023 Secure Boot CA rollover. It uses only the Python standard library and supports Python 3.9 and later.
- **Input formats** (detected automatically): raw ESL (`Get-SecureBootUEFI -OutputFilePath`, `efi-readvar`), Linux efivarfs files (with the 4-byte attribute prefix, or `--efivars` to read all four variables), and EFI_VARIABLE_AUTHENTICATION_2 update packages (`DBXUpdate.bin`, `*.efiauth2`).
- **Certificates:** identifies KEK CA 2011, KEK 2K CA 2023, Windows Production PCA 2011, UEFI CA 2011, Windows UEFI CA 2023, Microsoft UEFI CA 2023 and Option ROM UEFI CA 2023 by SHA-1 thumbprint. It parses X.509 notAfter with a small DER reader and flags expired certificates.
- **Update packages:** reports which certificates in the PKCS#7 signed a package, so you can see whether it is under the 2011 or the 2023 KEK.
- **dbx:** reports PCA 2011 revocation (the final CVE-2023-24932 step) and decodes Microsoft boot manager SVN entries (owner `9d132b6c-...`, app GUID, major.minor). It compares hashes and SVNs against Microsoft's `dbx_info_msft_latest.json`, and `--arch` limits the comparison to one architecture.
- **Findings:** OK, INFO, WARN and ACTION. Exit code 1 means at least one ACTION finding. `--json` gives machine-readable output.
- **Tests:** `test_sbrollover.py` has 28 unittest cases.
- **Fixtures:** 16 unmodified files from microsoft/secureboot_objects at `3d762ae`, which is BSD-2-Clause-Patent; `fixtures/NOTICE.md` has the license and the source path of each file.
- **CI:** `.github/workflows/rollover.yml` runs on ubuntu-24.04 with Python 3.9 and 3.13. It runs the unit tests plus two runs against the fixtures with an assertion on the result.

## 3. Evidence

### A, Windows (Windows 11 Home 10.0.26200; Windows PowerShell 5.1.26100 and pwsh 7.7.0)
The snippets were pulled out of the edited Windows.md with a regex and run verbatim. The only substitutions are the PFX password in place of Read-Host, and a fixed hash string in place of `Get-AppLockerFileInformation`, because the AppLocker module is not present on Windows Home. Microsoft's cmdlet docs show its hash as `0x`-prefixed.
```
=== original snippet (5.1)
...ToByte($hashString,Substring($i, 2) ...
Missing expression after ','.
=== comma fixed only (5.1)
Exception calling "ToByte" with "2" argument(s): "Could not find any recognizable digits."
PS> "0x0A1B...E8F0".Trim("0x")
A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F     # leading and trailing 0 lost
=== doc_hash (edited Windows.md, 5.1)
txt: 0A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F0
hsh: 32 bytes 0A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F0
=== doc_hash (pwsh 7): the line-67 Set-Content -Encoding byte failure is the PR #22 line, which I left unchanged
=== doc_cert (edited Windows.md), 5.1 and 7.7 both:
KEK.cer 766  KEK.pfx 2582  DBK.cer 766  DBK.pfx 2582
remaining in store: 0
PS> Get-Command makecert      -> (nothing; not on a stock Windows 11 install)
$ openssl x509 -inform der -in KEK.cer -noout -text | grep ...
subject=CN=Custom KEK   Public-Key: (2048 bit)   sha256WithRSAEncryption   Code Signing   Not After : Nov 18 05:17:41 2036 GMT
$ openssl pkcs12 -in KEK.pfx -passin pass:test -nodes | grep BEGIN
-----BEGIN PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
```
Only `Cert:\CurrentUser\My` was used, and every created certificate was removed. Secure Boot variables and LocalMachine stores were not touched.

### A, Linux (Docker on WSL: fedora:latest = Fedora 45, ubuntu:latest = Ubuntu 26.04.1)
The PE test file is a copy of the host's Microsoft-signed `bootmgfw.efi`, renamed to shimx64.efi. The keys are throwaway `openssl req ... -nodes` keys, and the module is 4 KiB of random bytes.
```
[fedora] pesign-116-9.fc45, kernel-devel-7.3.4-300.fc45
pesign -S -i=shimx64.efi           -> The signer's common name is Microsoft Windows   (so -i= works)
(cd elsewhere) pesign -S -i=shimx64.efi -> pesign: Error opening input: No such file or directory   (#25 reproduced)
pesign -r -i=shimx64.efi -o=shimx64.efi -> pesign: in-place file editing is not yet supported.  rc=0
pesign -r -i shimx64.efi -o o3.efi  -> pesign: Invalid signature number -1. Must be between 0 and 0.  rc=0
pesign -r -u 0 -i shimx64.efi -o o4.efi; pesign -S -i o4.efi -> No signatures found.
/usr/src/kernels/7.3.4-300.fc45.x86_64/scripts/sign-file sha512 DBK.key DBK.cer antimalware.ko -> rc=0
  4096 -> 4536 bytes, ends "~Module signature appended~"; rpm -qf sign-file -> kernel-devel-7.3.4-300.fc45.x86_64
  usage: scripts/sign-file [-dp] <hash algo> <key> <x509> <module> [<dest>]
dnf repoquery -l shim-x64 -> /boot/efi/EFI/fedora/shimx64.efi
[ubuntu] dpkg -S /usr/bin/kmodsign -> sbsigntool: /usr/bin/kmodsign
kmodsign sha512 DBK.key DBK.cer antimalware.ko -> rc=0, ends "~Module signature appended~"
pesign -r -u 0 -i shimx64.efi -o shimx64-nosig.efi; mv ...  -> rc=0, "No signatures found."
sbsign --key DBK.key --cert DBK.crt shimx64.efi; mv; mv     -> "Signing Unsigned original image" rc=0
sbverify --cert DBK.crt shimx64.efi -> Signature verification OK; pesign -S -> The signer's common name is Custom DBK
```

### B
```
$ python test_sbrollover.py              # Windows py3.12; WSL uv py3.9.25, 3.13.18, 3.14.10
Ran 28 tests in 0.019s
OK
GitHub Actions (fork): https://github.com/Dukotah/Hardware-and-Firmware-Security-Guidance/actions/runs/44244728981
  test (3.9) success / test (3.13) success, "Ran 28 tests ... OK"
(The first run failed: Python 3.9 is not available for the ubuntu-latest image, now Ubuntu 26.04. I pinned the runner to ubuntu-24.04.)

$ python sbrollover.py --db fixtures/DBUpdate2024.bin --dbx fixtures/dbx_x64.efiauth2 --dbx-reference fixtures/dbx_info_msft_latest.json
== db (auth2)
   signed by: Microsoft Windows UEFI Key Exchange Key (issuer Microsoft Corporation KEK CA 2011, expires 2024-01-31)
   X509   Windows UEFI CA 2023  [Windows UEFI CA 2023]  sha1=45a0fa32604773c82433c3b7d59e7466b3ac0c67  notAfter=2035-06-13
== dbx (auth2)
   signed by: Microsoft Windows UEFI Key Exchange Key (issuer Microsoft Corporation KEK 2K CA 2023, expires 2027-03-03)
   SHA256 hashes: 291
== findings
   [OK] db trusts Windows UEFI CA 2023: boot managers signed by the 2023 CA will boot.
   [INFO] dbx does not revoke Microsoft Windows Production PCA 2011; ...
   [WARN] dbx SVN for bootmgfw.efi (EFI_BOOTMGR_DBXSVN_GUID) is absent, reference requires 12.0.
$ python sbrollover.py --dbx fixtures/DBXUpdate.bin --dbx-reference ... --arch x64
   reference: 443/445 known revoked hashes present, 0 not in reference
```
This last run is a real finding in Microsoft's own data: the amd64 `DBXUpdate.bin` at `3d762ae` is 2 hashes behind `dbx_info_msft_latest.json` (x64).

I could not read this machine's live Secure Boot state. The shell is not elevated (`Confirm-SecureBootUEFI` returns "Unable to set proper privileges. Access was denied."), and WSL has no efivarfs. Nothing was written to firmware.

## 4. Competing work check
- `gh pr list -R nsacyber/Hardware-and-Firmware-Security-Guidance --state all -L 50`, run at start and before finishing, shows only #19 (merged), #22, #27 and #28. None of the AI-PR spray accounts appear.
- [#22](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance/pull/22) changes Windows.md line 67 only. Branch A changes lines 62 and 65 and leaves 67 alone. The hunks are adjacent, so whichever PR merges second may need a trivial rebase.
- [#27](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance/pull/27) and [#28](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance/pull/28) change `esl-parser.py` only (fixing #29 and #30). There is no overlap.
- [#24](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance/issues/24), [#25](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance/issues/25) and [#26](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance/issues/26) are open, unassigned, and have no linked PR.

## 5. Draft upstream text

### PR (from `Dukotah:fix/secureboot-docs` to `nsacyber:master`)
**Title:** Fix Secure Boot signing snippets and add Fedora/SDK-free options

**Body:**
```
Fixes #24
Fixes #25
Fixes #26

Docs-only fixes to secureboot/Windows.md and secureboot/Linux.md. Every command was run before and after the change.

Windows.md
- 2.4 hash snippet: `$hashString,Substring(...)` is a parse error ("Missing expression after ','"). With the dot fixed it still throws
  "Could not find any recognizable digits": the `0x` prefix from Get-AppLockerFileInformation was only trimmed in the
  value written to shimx64.txt, not in `$hashString`. `Trim("0x")` also strips leading and trailing zero digits from the hash.
  The prefix is now removed once with `-replace '^0x', ''`. The `set-content -encoding byte` line (PowerShell 7) is left to #22.
- 2.1 (#24): makecert is not built into Windows; it ships with the Windows SDK and is deprecated
  (https://learn.microsoft.com/windows/win32/seccrypto/makecert). Added a New-SelfSignedCertificate alternative
  that exports the same DER .cer files plus password-protected .pfx files and removes the key from the user store.
  Tested on Windows PowerShell 5.1 and PowerShell 7.7; openssl reads the outputs as RSA-2048/SHA-256 DER certs and PKCS#12.

Linux.md
- 2.4 (#26): kmodsign is Ubuntu-only (package sbsigntool). Added the kernel's sign-file, shipped in kernel-devel on
  Fedora/RHEL, which takes the same arguments (https://docs.kernel.org/admin-guide/module-signing.html).
  Tested: kmodsign on Ubuntu 26.04 and sign-file on Fedora 45 both append "~Module signature appended~".
- 2.3/2.9 (#25): the "Error opening input: No such file or directory" in #25 occurs when shimx64.efi is not in the
  working directory. Noted where Shim lives (/boot/efi/EFI/fedora/shimx64.efi on Fedora) and used `-i shimx64.efi`
  as in section 2.5.
- 2.3/2.10: `pesign -r -i=shimx64.efi -o=shimx64.efi` fails with "in-place file editing is not yet supported" and,
  without -u, "Invalid signature number -1". Replaced with `pesign -r -u 0 -i shimx64.efi -o shimx64-nosig.efi` + mv.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

No separate issue is needed for the unfiled line-65 bug and the pesign `-r` bug; the PR body describes both. If the owner would rather file issues first, here is paste-ready text:

**Issue title:** Windows.md 2.4 hash snippet and Linux.md pesign -r commands fail as written
```
secureboot/Windows.md section 2.4: `[convert]::ToByte($hashString,Substring($i, 2), 16)` is a PowerShell parse error
(comma instead of dot). After fixing that, the loop still throws "Could not find any recognizable digits" because the
"0x" prefix is never removed from $hashString (only from the text written to shimx64.txt), and Trim("0x") also strips
leading/trailing 0 digits of the hash.

secureboot/Linux.md sections 2.3 and 2.10: `pesign -r -i=shimx64.efi -o=shimx64.efi` prints "in-place file editing is
not yet supported" (pesign 116) and, without `-u 0`, "Invalid signature number -1"; both errors still exit 0.
Working form: `pesign -r -u 0 -i shimx64.efi -o shimx64-nosig.efi && mv shimx64-nosig.efi shimx64.efi`.
```

## 6. Land probability
**Low.** Only one PR has merged in the repo's history, #22 has waited more than 3 years, and the maintainer edits README.md directly. The change is small, docs-only and closes three open issues, which is the best shape this repo allows.

The owner should:
1. Review the A diff (`git diff upstream/master fix/secureboot-docs`).
2. Optionally test the New-SelfSignedCertificate block and Get-AppLockerFileInformation on a Windows Pro/Enterprise machine, since Home lacks AppLocker so I used a stand-in hash.
3. Open the PR with the text above.
4. Point readers at branch B from the fork README if wanted.
5. Optionally run `sudo python3 secureboot/rollover/sbrollover.py --efivars` on a real Linux box, or run it on elevated `Get-SecureBootUEFI` exports, to check live hardware output.
