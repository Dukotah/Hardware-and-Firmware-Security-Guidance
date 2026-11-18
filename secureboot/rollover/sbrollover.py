#!/usr/bin/env python3
"""Read-only Secure Boot signature database checker for the Microsoft 2011 -> 2023 CA rollover.

Parses EFI_SIGNATURE_LIST data from any of:
  - raw ESL files (Get-SecureBootUEFI -OutputFilePath, efi-readvar -o, esl-parser inputs)
  - Linux efivarfs dumps (4-byte attribute prefix, e.g. /sys/firmware/efi/efivars/db-d719b2cb-...)
  - authenticated variable updates (EFI_VARIABLE_AUTHENTICATION_2 header, e.g. DBXUpdate.bin, *.efiauth2)

and reports which Microsoft Secure Boot certificates are present, when they expire, which signer
certificates an authenticated update carries, the dbx revocation status (Windows Production PCA 2011,
boot manager SVNs, known revoked image hashes) and a rollover readiness summary.

The tool never writes firmware variables. Python standard library only.
"""

import argparse
import datetime
import glob
import hashlib
import json
import os
import struct
import sys
import uuid

# Signature types (UEFI 2.10, section 32.4.1)
EFI_CERT_SHA256_GUID = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")
EFI_CERT_RSA2048_GUID = uuid.UUID("3c5766e8-269c-4e34-aa14-ed776e85b3b6")
EFI_CERT_SHA1_GUID = uuid.UUID("826ca512-cf10-4ac9-b187-be01496631bd")
EFI_CERT_X509_GUID = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
EFI_CERT_X509_SHA256_GUID = uuid.UUID("3bd2a492-96c0-4079-b420-fcf98ef103ed")
EFI_CERT_X509_SHA384_GUID = uuid.UUID("7076876e-80c2-4ee6-aad2-28b349a6865b")
EFI_CERT_X509_SHA512_GUID = uuid.UUID("446dbf63-2502-4cda-bcfa-2465d2b0fe9d")
EFI_CERT_TYPE_PKCS7_GUID = uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7")
WIN_CERT_TYPE_EFI_GUID = 0x0EF1

SIG_TYPE_NAMES = {
    EFI_CERT_SHA256_GUID: "SHA256",
    EFI_CERT_RSA2048_GUID: "RSA2048",
    EFI_CERT_SHA1_GUID: "SHA1",
    EFI_CERT_X509_GUID: "X509",
    EFI_CERT_X509_SHA256_GUID: "X509_SHA256",
    EFI_CERT_X509_SHA384_GUID: "X509_SHA384",
    EFI_CERT_X509_SHA512_GUID: "X509_SHA512",
}

MICROSOFT_OWNER_GUID = uuid.UUID("77fa9abd-0359-4d32-bd60-28f4e78f784b")
# Owner GUID Microsoft uses for boot manager Security Version Number (SVN) entries in dbx
MICROSOFT_SVN_OWNER_GUID = uuid.UUID("9d132b6c-59d5-4388-ab1c-185cfcb2eb92")
SVN_APP_GUIDS = {
    uuid.UUID("9d132b61-59d5-4388-ab1c-185c3cb2eb92"): "bootmgfw.efi (EFI_BOOTMGR_DBXSVN_GUID)",
    uuid.UUID("e8f82e9d-e127-4158-a488-4c18abe2f284"): "cdboot.efi (EFI_CDBOOT_DBXSVN_GUID)",
    uuid.UUID("c999cac2-7ffe-496f-8127-9e2a8a535976"): "wdsmgfw.efi (EFI_WDSMGR_DBXSVN_GUID)",
}

EFI_GLOBAL_VARIABLE = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
EFI_IMAGE_SECURITY_DATABASE = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
EFIVARS_DIR = "/sys/firmware/efi/efivars"

# SHA-1 thumbprints of the DER certificates published in github.com/microsoft/secureboot_objects
MICROSOFT_CERTS = {
    "31590bfd89c9d74ed087dfac66334b3931254b30": {
        "key": "kek2011", "name": "Microsoft Corporation KEK CA 2011", "var": "KEK", "generation": 2011},
    "459ab6fb5e284d272d5e3e6abc8ed663829d632b": {
        "key": "kek2023", "name": "Microsoft Corporation KEK 2K CA 2023", "var": "KEK", "generation": 2023},
    "580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d": {
        "key": "pca2011", "name": "Microsoft Windows Production PCA 2011", "var": "db", "generation": 2011},
    "46def63b5ce61cf8ba0de2e6639c1019d0ed14f3": {
        "key": "uefica2011", "name": "Microsoft Corporation UEFI CA 2011", "var": "db", "generation": 2011},
    "45a0fa32604773c82433c3b7d59e7466b3ac0c67": {
        "key": "windowsuefica2023", "name": "Windows UEFI CA 2023", "var": "db", "generation": 2023},
    "b5eeb4a6706048073f0ed296e7f580a790b59eaa": {
        "key": "uefica2023", "name": "Microsoft UEFI CA 2023", "var": "db", "generation": 2023},
    "3fb39e2b8bd183bf9e4594e72183ca60afcd4277": {
        "key": "oromca2023", "name": "Microsoft Option ROM UEFI CA 2023", "var": "db", "generation": 2023},
}
KEY_TO_THUMB = {v["key"]: k for k, v in MICROSOFT_CERTS.items()}


class ParseError(Exception):
    pass


# ---------------------------------------------------------------- minimal DER reader

def der_read(buf, off):
    """Return (tag, content_start, content_end) for the DER TLV at off."""
    if off + 2 > len(buf):
        raise ParseError("truncated DER")
    tag = buf[off]
    length = buf[off + 1]
    pos = off + 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(buf):
            raise ParseError("bad DER length")
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    if pos + length > len(buf):
        raise ParseError("DER element overruns buffer")
    return tag, pos, pos + length


def der_children(buf, start, end):
    out = []
    off = start
    while off < end:
        tag, cs, ce = der_read(buf, off)
        out.append((tag, cs, ce, off))
        off = ce
    return out


def _decode_oid(raw):
    parts = [raw[0] // 40, raw[0] % 40]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def _decode_time(tag, raw):
    s = raw.decode("ascii").rstrip("Z")
    if tag == 0x17:  # UTCTime YYMMDDHHMMSS
        year = int(s[0:2])
        year += 2000 if year < 50 else 1900
        s = str(year) + s[2:]
    return datetime.datetime(int(s[0:4]), int(s[4:6]), int(s[6:8]), int(s[8:10]), int(s[10:12]),
                             int(s[12:14]) if len(s) >= 14 else 0, tzinfo=datetime.timezone.utc)


def _name_cn(buf, start, end):
    for _, ss, se, _ in der_children(buf, start, end):        # RDN SET
        for _, as_, ae, _ in der_children(buf, ss, se):       # AttributeTypeAndValue SEQ
            kids = der_children(buf, as_, ae)
            if len(kids) == 2 and kids[0][0] == 0x06 and _decode_oid(buf[kids[0][1]:kids[0][2]]) == "2.5.4.3":
                return buf[kids[1][1]:kids[1][2]].decode("utf-8", "replace")
    return None


def parse_certificate(der):
    """Parse the fields this tool needs from a DER X.509 certificate."""
    der = bytes(der)
    tag, cs, ce = der_read(der, 0)
    if tag != 0x30:
        raise ParseError("certificate is not a SEQUENCE")
    tbs = der_children(der, cs, ce)[0]
    fields = der_children(der, tbs[1], tbs[2])
    if fields and fields[0][0] == 0xA0:   # explicit version
        fields = fields[1:]
    # serial, signature, issuer, validity, subject
    issuer, validity, subject = fields[2], fields[3], fields[4]
    times = der_children(der, validity[1], validity[2])
    return {
        "subject_cn": _name_cn(der, subject[1], subject[2]),
        "issuer_cn": _name_cn(der, issuer[1], issuer[2]),
        "not_before": _decode_time(times[0][0], der[times[0][1]:times[0][2]]),
        "not_after": _decode_time(times[1][0], der[times[1][1]:times[1][2]]),
        "sha1": hashlib.sha1(der[:ce]).hexdigest(),
        "sha256": hashlib.sha256(der[:ce]).hexdigest(),
    }


def pkcs7_certificates(der):
    """Return the DER certificates embedded in a PKCS#7 SignedData (bare or ContentInfo-wrapped)."""
    der = bytes(der)
    tag, cs, ce = der_read(der, 0)
    kids = der_children(der, cs, ce)
    if kids and kids[0][0] == 0x06:   # ContentInfo { OID signedData, [0] SignedData }
        _, sds, sde = der_read(der, kids[1][1])
        kids = der_children(der, sds, sde)
    certs = []
    for k in kids:
        if k[0] == 0xA0:              # certificates [0] IMPLICIT SET OF Certificate
            for c in der_children(der, k[1], k[2]):
                if c[0] == 0x30:
                    certs.append(der[c[3]:c[2]])
    return certs


# ---------------------------------------------------------------- ESL / variable parsing

def parse_esl(data):
    """Parse concatenated EFI_SIGNATURE_LISTs. Returns a list of dicts."""
    data = bytes(data)
    lists = []
    off = 0
    while off < len(data):
        if len(data) - off < 28:
            raise ParseError(f"trailing {len(data) - off} bytes at offset {off} are too short for an ESL header")
        sig_type = uuid.UUID(bytes_le=data[off:off + 16])
        list_size, header_size, sig_size = struct.unpack_from("<III", data, off + 16)
        if list_size < 28 or off + list_size > len(data):
            raise ParseError(f"bad SignatureListSize {list_size} at offset {off}")
        if sig_size < 16 or (list_size - 28 - header_size) % sig_size:
            raise ParseError(f"bad SignatureSize {sig_size} at offset {off}")
        entries = []
        pos = off + 28 + header_size
        while pos < off + list_size:
            owner = uuid.UUID(bytes_le=data[pos:pos + 16])
            entries.append({"owner": owner, "data": data[pos + 16:pos + sig_size]})
            pos += sig_size
        lists.append({"type": sig_type, "type_name": SIG_TYPE_NAMES.get(sig_type, str(sig_type)),
                      "offset": off, "entries": entries})
        off += list_size
    return lists


def _looks_like_esl(data):
    if len(data) == 0:
        return True
    try:
        lists = parse_esl(data)
    except ParseError:
        return False
    return all(lst["type"] in SIG_TYPE_NAMES for lst in lists)


def load_variable(data):
    """Detect the container format and return (format, esl_bytes, signer_certs_der)."""
    data = bytes(data)
    # EFI_VARIABLE_AUTHENTICATION_2: EFI_TIME (16) + WIN_CERTIFICATE_UEFI_GUID
    if len(data) >= 40:
        dw_length, revision, cert_type = struct.unpack_from("<IHH", data, 16)
        if (revision == 0x0200 and cert_type == WIN_CERT_TYPE_EFI_GUID
                and uuid.UUID(bytes_le=data[24:40]) == EFI_CERT_TYPE_PKCS7_GUID
                and 24 <= dw_length <= len(data) - 16):
            pkcs7 = data[40:16 + dw_length]
            try:
                signers = pkcs7_certificates(pkcs7)
            except ParseError:
                signers = []
            return "auth2", data[16 + dw_length:], signers
    if _looks_like_esl(data):
        return "esl", data, []
    # efivarfs: UINT32 attributes, then the variable data
    if len(data) >= 4 and _looks_like_esl(data[4:]):
        return "efivarfs", data[4:], []
    raise ParseError("not an ESL, efivarfs dump or EFI_VARIABLE_AUTHENTICATION_2 payload")


def decode_svn(entry_data):
    """Decode a Microsoft dbx SVN entry: 0x01, app GUID, UINT16 minor, UINT16 major, zero pad."""
    if len(entry_data) != 32 or entry_data[0] != 0x01:
        return None
    app = uuid.UUID(bytes_le=entry_data[1:17])
    minor, major = struct.unpack_from("<HH", entry_data, 17)
    return {"app_guid": app, "app": SVN_APP_GUIDS.get(app, str(app)), "version": f"{major}.{minor}"}


def summarize(esl_bytes):
    """Return certificates, hashes and SVN entries found in ESL bytes."""
    certs, hashes, svns, other = [], [], [], []
    for lst in parse_esl(esl_bytes):
        for e in lst["entries"]:
            if lst["type"] == EFI_CERT_X509_GUID:
                try:
                    info = parse_certificate(e["data"])
                except (ParseError, IndexError, ValueError) as exc:
                    info = {"error": str(exc), "sha1": hashlib.sha1(e["data"]).hexdigest()}
                info["owner"] = e["owner"]
                info["microsoft"] = MICROSOFT_CERTS.get(info["sha1"])
                certs.append(info)
            elif lst["type"] == EFI_CERT_SHA256_GUID:
                svn = decode_svn(e["data"]) if e["owner"] == MICROSOFT_SVN_OWNER_GUID else None
                if svn:
                    svns.append(svn)
                else:
                    hashes.append(e["data"].hex().upper())
            else:
                other.append(lst["type_name"])
    return {"certs": certs, "hashes": hashes, "svns": svns, "other": other}


# ---------------------------------------------------------------- reference data

def load_dbx_reference(path, arch=None):
    """Load Microsoft's dbx_info_msft_*.json (github.com/microsoft/secureboot_objects).

    arch limits the revoked image hashes to one architecture (x64, ia32, aarch64, arm)."""
    with open(path, "r", encoding="utf-8") as f:
        ref = json.load(f)
    hashes = {}
    for image_arch, images in ref.get("images", {}).items():
        if arch and image_arch != arch:
            continue
        for img in images:
            h = img.get("authenticodeHash", "").upper()
            if h:
                hashes.setdefault(h, []).append(image_arch)
    svns = {}
    for s in ref.get("svns", []):
        d = decode_svn(bytes.fromhex(s["value"]))
        if d:
            svns[d["app_guid"]] = {"version": d["version"], "description": s.get("description", "")}
    certs = {c["thumbprint"].lower(): c.get("description", "") for c in ref.get("certificates", [])}
    return {"hashes": hashes, "svns": svns, "certs": certs}


def _version_tuple(v):
    return tuple(int(x) for x in v.split("."))


# ---------------------------------------------------------------- report

def analyze(variables, dbx_reference=None, now=None):
    """variables: dict name -> (format, summary, signers). Returns a report dict."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    report = {"variables": {}, "findings": []}
    present = {}
    for name, (fmt, summ, signers) in variables.items():
        var = {"format": fmt, "certificates": [], "hash_count": len(summ["hashes"]),
               "svns": summ["svns"], "other_types": sorted(set(summ["other"])), "signers": []}
        for c in summ["certs"]:
            var["certificates"].append({
                "subject": c.get("subject_cn"), "sha1": c["sha1"],
                "not_after": c["not_after"].strftime("%Y-%m-%d") if "not_after" in c else None,
                "expired": bool("not_after" in c and c["not_after"] < now),
                "microsoft": c["microsoft"]["name"] if c["microsoft"] else None,
            })
            if c["microsoft"]:
                present.setdefault(name.lower(), set()).add(c["microsoft"]["key"])
        for s in signers:
            try:
                p = parse_certificate(s)
                var["signers"].append({"subject": p["subject_cn"], "issuer": p["issuer_cn"],
                                       "not_after": p["not_after"].strftime("%Y-%m-%d")})
            except (ParseError, IndexError, ValueError):
                pass
        if dbx_reference is not None and name.lower() == "dbx":
            hs = set(summ["hashes"])
            ref_h = set(dbx_reference["hashes"])
            var["reference"] = {
                "known_revoked_hashes": len(ref_h),
                "present": len(hs & ref_h),
                "missing": len(ref_h - hs),
                "extra_not_in_reference": len(hs - ref_h),
            }
            svn_status = []
            have = {s["app_guid"]: s["version"] for s in summ["svns"]}
            for app_guid, want in dbx_reference["svns"].items():
                got = have.get(app_guid)
                svn_status.append({
                    "app": SVN_APP_GUIDS.get(app_guid, str(app_guid)), "required": want["version"],
                    "present": got,
                    "current": bool(got and _version_tuple(got) >= _version_tuple(want["version"])),
                })
            var["reference"]["svns"] = svn_status
        report["variables"][name] = var

    kek = present.get("kek", set())
    db = present.get("db", set())
    dbx = present.get("dbx", set())
    f = report["findings"]

    def add(level, msg):
        f.append({"level": level, "message": msg})

    if "kek" in present or "KEK" in variables:
        if "kek2023" in kek:
            add("OK", "KEK contains Microsoft Corporation KEK 2K CA 2023: future Microsoft db/dbx updates can be applied.")
        else:
            add("ACTION", "KEK lacks Microsoft Corporation KEK 2K CA 2023: db/dbx updates signed with the 2023 KEK "
                          "cannot be applied until a PK-signed KEK update adds it.")
    if "db" in present or "db" in variables:
        if "windowsuefica2023" in db:
            add("OK", "db trusts Windows UEFI CA 2023: boot managers signed by the 2023 CA will boot.")
        else:
            add("ACTION", "db lacks Windows UEFI CA 2023: Windows boot media signed by the 2023 CA will not boot.")
        if "uefica2011" in db and "uefica2023" not in db:
            add("ACTION", "db trusts Microsoft UEFI CA 2011 (third-party: shim, Linux, option ROMs) but not "
                          "Microsoft UEFI CA 2023: newly signed third-party binaries will not boot.")
        if "uefica2011" in db and "oromca2023" not in db:
            add("WARN", "db trusts Microsoft UEFI CA 2011 but not Microsoft Option ROM UEFI CA 2023: option ROMs "
                        "re-signed by the 2023 CA will be rejected.")
        if "uefica2011" not in db and ("uefica2023" in db or "oromca2023" in db):
            add("WARN", "db trusts a 2023 third-party CA without the 2011 one; Microsoft recommends adding those only "
                        "where Microsoft UEFI CA 2011 was already trusted.")
    if "dbx" in present or "dbx" in variables:
        if "pca2011" in dbx:
            add("OK", "dbx revokes Microsoft Windows Production PCA 2011 (CVE-2023-24932 / BlackLotus final mitigation).")
            if "db" in variables and "windowsuefica2023" not in db:
                add("ACTION", "PCA 2011 is revoked but db has no Windows UEFI CA 2023: Windows cannot boot.")
        else:
            add("INFO", "dbx does not revoke Microsoft Windows Production PCA 2011; boot managers vulnerable to "
                        "CVE-2023-24932 still pass Secure Boot unless their hashes or SVN are revoked.")
        ref = report["variables"].get("dbx", {}).get("reference")
        if ref:
            if ref["missing"]:
                add("WARN", f"dbx is missing {ref['missing']} of {ref['known_revoked_hashes']} image hashes Microsoft "
                            "lists as revoked (use --arch to compare against one architecture only).")
            for s in ref["svns"]:
                if not s["current"]:
                    add("WARN", f"dbx SVN for {s['app']} is {s['present'] or 'absent'}, reference requires {s['required']}.")
    for name, var in report["variables"].items():
        for c in var["certificates"]:
            if c["microsoft"] and c["expired"] and name.lower() != "dbx":
                add("INFO", f"{name}: {c['microsoft']} expired {c['not_after']}. Microsoft no longer "
                            "signs new boot components or updates with it; add its 2023 replacement.")
    return report


def print_report(report, out=None):
    out = out or sys.stdout
    for name, var in report["variables"].items():
        print(f"== {name} ({var['format']})", file=out)
        for s in var["signers"]:
            print(f"   signed by: {s['subject']} (issuer {s['issuer']}, expires {s['not_after']})", file=out)
        for c in var["certificates"]:
            tag = c["microsoft"] or "non-Microsoft"
            exp = " EXPIRED" if c["expired"] else ""
            print(f"   X509   {c['subject']}  [{tag}]  sha1={c['sha1']}  notAfter={c['not_after']}{exp}", file=out)
        if var["hash_count"]:
            print(f"   SHA256 hashes: {var['hash_count']}", file=out)
        for s in var["svns"]:
            print(f"   SVN    {s['app']} >= {s['version']}", file=out)
        if var["other_types"]:
            print(f"   other signature types: {', '.join(var['other_types'])}", file=out)
        ref = var.get("reference")
        if ref:
            print(f"   reference: {ref['present']}/{ref['known_revoked_hashes']} known revoked hashes present, "
                  f"{ref['extra_not_in_reference']} not in reference", file=out)
    print("== findings", file=out)
    for f in report["findings"]:
        print(f"   [{f['level']}] {f['message']}", file=out)


def _json_default(o):
    if isinstance(o, uuid.UUID):
        return str(o)
    raise TypeError(type(o))


def read_efivars(directory=EFIVARS_DIR):
    found = {}
    for name, guid in (("PK", EFI_GLOBAL_VARIABLE), ("KEK", EFI_GLOBAL_VARIABLE),
                       ("db", EFI_IMAGE_SECURITY_DATABASE), ("dbx", EFI_IMAGE_SECURITY_DATABASE)):
        path = os.path.join(directory, f"{name}-{guid}")
        if os.path.exists(path):
            found[name] = path
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only check of Secure Boot PK/KEK/db/dbx contents for the Microsoft 2011 -> 2023 CA rollover.")
    parser.add_argument("--pk", help="PK export (ESL, efivarfs dump or authenticated update)")
    parser.add_argument("--kek", help="KEK export")
    parser.add_argument("--db", help="db export")
    parser.add_argument("--dbx", help="dbx export")
    parser.add_argument("--efivars", nargs="?", const=EFIVARS_DIR, metavar="DIR",
                        help=f"read PK/KEK/db/dbx from efivarfs (default {EFIVARS_DIR}); read-only")
    parser.add_argument("--dbx-reference", metavar="JSON",
                        help="Microsoft dbx_info_msft_*.json to compare dbx against")
    parser.add_argument("--arch", choices=("x64", "ia32", "aarch64", "arm"),
                        help="compare dbx only against this architecture's revoked hashes")
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args(argv)

    paths = {}
    if args.efivars:
        paths.update(read_efivars(args.efivars))
        if not paths:
            print(f"Error: no Secure Boot variables found in {args.efivars}", file=sys.stderr)
            return 2
    for name in ("pk", "kek", "db", "dbx"):
        p = getattr(args, name)
        if p:
            paths[{"pk": "PK", "kek": "KEK"}.get(name, name)] = p
    if not paths:
        parser.error("give at least one of --pk/--kek/--db/--dbx or --efivars")

    variables = {}
    for name, path in paths.items():
        try:
            with open(path, "rb") as f:
                data = f.read()
            fmt, esl, signers = load_variable(data)
            variables[name] = (fmt, summarize(esl), signers)
        except (OSError, ParseError) as exc:
            print(f"Error: {name} ({path}): {exc}", file=sys.stderr)
            return 3
    ref = load_dbx_reference(args.dbx_reference, args.arch) if args.dbx_reference else None
    report = analyze(variables, ref)
    if args.json:
        json.dump(report, sys.stdout, indent=2, default=_json_default)
        print()
    else:
        print_report(report)
    return 1 if any(f["level"] == "ACTION" for f in report["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
