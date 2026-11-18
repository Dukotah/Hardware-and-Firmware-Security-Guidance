"""Unit tests for sbrollover.py. Fixtures are Microsoft's published Secure Boot objects (see fixtures/NOTICE.md)."""

import datetime
import io
import json
import os
import struct
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sbrollover as sb  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
CERT_FILES = {
    "kek2011": "MicCorKEKCA2011_2011-06-24.der",
    "kek2023": "microsoft corporation kek 2k ca 2023.der",
    "pca2011": "MicWinProPCA2011_2011-10-19.der",
    "uefica2011": "MicCorUEFCA2011_2011-06-27.der",
    "windowsuefica2023": "windows uefi ca 2023.der",
    "uefica2023": "microsoft uefi ca 2023.der",
    "oromca2023": "microsoft option rom uefi ca 2023.der",
}
NOW = datetime.datetime(2026, 11, 17, tzinfo=datetime.timezone.utc)


def fixture(name):
    with open(os.path.join(FIX, name), "rb") as f:
        return f.read()


def make_esl(sig_type, owner, entries):
    """Build one EFI_SIGNATURE_LIST the way efitools' cert-to-efi-sig-list does."""
    size = 16 + len(entries[0])
    assert all(len(e) == len(entries[0]) for e in entries)
    body = b"".join(owner.bytes_le + e for e in entries)
    return sig_type.bytes_le + struct.pack("<III", 28 + len(body), 0, size) + body


def cert_esl(*keys):
    return b"".join(make_esl(sb.EFI_CERT_X509_GUID, sb.MICROSOFT_OWNER_GUID, [fixture(CERT_FILES[k])])
                    for k in keys)


def run_vars(now=NOW, ref=None, **variables):
    parsed = {}
    for name, data in variables.items():
        fmt, esl, signers = sb.load_variable(data)
        parsed[name] = (fmt, sb.summarize(esl), signers)
    return sb.analyze(parsed, ref, now=now)


def levels(report, level):
    return [f["message"] for f in report["findings"] if f["level"] == level]


class CertificateParsing(unittest.TestCase):
    def test_thumbprints_match_published_der_files(self):
        for key, fname in CERT_FILES.items():
            info = sb.parse_certificate(fixture(fname))
            self.assertIn(info["sha1"], sb.MICROSOFT_CERTS, fname)
            self.assertEqual(sb.MICROSOFT_CERTS[info["sha1"]]["key"], key)
            self.assertEqual(info["subject_cn"], sb.MICROSOFT_CERTS[info["sha1"]]["name"])

    def test_validity_dates(self):
        kek2011 = sb.parse_certificate(fixture(CERT_FILES["kek2011"]))
        self.assertEqual(kek2011["not_after"].date(), datetime.date(2026, 6, 24))
        pca = sb.parse_certificate(fixture(CERT_FILES["pca2011"]))
        self.assertEqual(pca["not_after"].date(), datetime.date(2026, 10, 19))
        win2023 = sb.parse_certificate(fixture(CERT_FILES["windowsuefica2023"]))
        self.assertEqual(win2023["not_before"].year, 2023)
        self.assertGreater(win2023["not_after"].year, 2030)

    def test_truncated_certificate_raises(self):
        with self.assertRaises(sb.ParseError):
            sb.parse_certificate(fixture(CERT_FILES["kek2011"])[:100])


class EslParsing(unittest.TestCase):
    def test_round_trip(self):
        esl = cert_esl("kek2011", "kek2023")
        lists = sb.parse_esl(esl)
        self.assertEqual([lst["type_name"] for lst in lists], ["X509", "X509"])
        self.assertEqual(lists[1]["entries"][0]["owner"], sb.MICROSOFT_OWNER_GUID)

    def test_hash_list(self):
        hashes = [bytes([i]) * 32 for i in range(3)]
        lists = sb.parse_esl(make_esl(sb.EFI_CERT_SHA256_GUID, sb.MICROSOFT_OWNER_GUID, hashes))
        self.assertEqual([e["data"] for e in lists[0]["entries"]], hashes)

    def test_bad_size_rejected(self):
        esl = bytearray(cert_esl("kek2011"))
        struct.pack_into("<I", esl, 16, len(esl) + 10)
        with self.assertRaises(sb.ParseError):
            sb.parse_esl(bytes(esl))

    def test_empty_variable(self):
        self.assertEqual(sb.parse_esl(b""), [])


class ContainerDetection(unittest.TestCase):
    def test_raw_esl(self):
        fmt, esl, signers = sb.load_variable(cert_esl("kek2023"))
        self.assertEqual((fmt, signers), ("esl", []))

    def test_efivarfs_prefix(self):
        attrs = struct.pack("<I", 0x27)   # NV | BS | RT | TIME_BASED_AUTHENTICATED_WRITE_ACCESS
        fmt, esl, _ = sb.load_variable(attrs + cert_esl("windowsuefica2023"))
        self.assertEqual(fmt, "efivarfs")
        self.assertEqual(sb.summarize(esl)["certs"][0]["microsoft"]["key"], "windowsuefica2023")

    def test_garbage_rejected(self):
        with self.assertRaises(sb.ParseError):
            sb.load_variable(b"\xff" * 64)

    def test_db_update_2024_auth2(self):
        fmt, esl, signers = sb.load_variable(fixture("DBUpdate2024.bin"))
        self.assertEqual(fmt, "auth2")
        certs = sb.summarize(esl)["certs"]
        self.assertEqual([c["microsoft"]["key"] for c in certs], ["windowsuefica2023"])
        issuers = {sb.parse_certificate(s)["issuer_cn"] for s in signers}
        self.assertIn("Microsoft Corporation KEK CA 2011", issuers)

    def test_third_party_and_option_rom_updates(self):
        for fname, key in (("DBUpdate3P2023.bin", "uefica2023"), ("DBUpdateOROM2023.bin", "oromca2023")):
            _, esl, _ = sb.load_variable(fixture(fname))
            self.assertEqual([c["microsoft"]["key"] for c in sb.summarize(esl)["certs"]], [key], fname)

    def test_dbx_update_hashes(self):
        fmt, esl, _ = sb.load_variable(fixture("DBXUpdate.bin"))
        summ = sb.summarize(esl)
        self.assertEqual(fmt, "auth2")
        self.assertEqual(len(summ["hashes"]), 443)
        self.assertEqual(summ["svns"], [])

    def test_kek2023_signed_dbx(self):
        _, esl, signers = sb.load_variable(fixture("dbx_x64.efiauth2"))
        self.assertEqual(len(sb.summarize(esl)["hashes"]), 291)
        issuers = {sb.parse_certificate(s)["issuer_cn"] for s in signers}
        self.assertIn("Microsoft Corporation KEK 2K CA 2023", issuers)

    def test_svn_update(self):
        _, esl, _ = sb.load_variable(fixture("DBXUpdateSVN.bin"))
        summ = sb.summarize(esl)
        self.assertEqual(summ["hashes"], [])
        apps = {s["app"].split()[0] for s in summ["svns"]}
        self.assertEqual(apps, {"bootmgfw.efi", "cdboot.efi", "wdsmgfw.efi"})


class SvnDecoding(unittest.TestCase):
    def test_reference_value(self):
        raw = bytes.fromhex("01612B139DD5598843AB1C185C3CB2EB9200000C000000000000000000000000")
        d = sb.decode_svn(raw)
        self.assertEqual(d["app_guid"], uuid.UUID("9d132b61-59d5-4388-ab1c-185c3cb2eb92"))
        self.assertEqual(d["version"], "12.0")

    def test_not_svn(self):
        self.assertIsNone(sb.decode_svn(b"\x00" * 32))


class RolloverFindings(unittest.TestCase):
    def test_legacy_only_system(self):
        r = run_vars(KEK=cert_esl("kek2011"), db=cert_esl("pca2011", "uefica2011"),
                     dbx=fixture("DBXUpdate.bin"))
        actions = " ".join(levels(r, "ACTION"))
        self.assertIn("KEK 2K CA 2023", actions)
        self.assertIn("Windows UEFI CA 2023", actions)
        self.assertIn("Microsoft UEFI CA 2023", actions)
        self.assertTrue(any("does not revoke" in m for m in levels(r, "INFO")))
        self.assertTrue(any("KEK CA 2011 expired 2026-06-24" in m for m in levels(r, "INFO")))

    def test_fully_rolled_system(self):
        dbx = cert_esl("pca2011") + sb.load_variable(fixture("DBXUpdate.bin"))[1]
        r = run_vars(KEK=cert_esl("kek2011", "kek2023"),
                     db=cert_esl("pca2011", "uefica2011", "windowsuefica2023", "uefica2023", "oromca2023"),
                     dbx=dbx)
        self.assertEqual(levels(r, "ACTION"), [])
        self.assertEqual(levels(r, "WARN"), [])
        self.assertTrue(any("revokes Microsoft Windows Production PCA 2011" in m for m in levels(r, "OK")))

    def test_pca_revoked_without_2023_ca_is_unbootable(self):
        r = run_vars(db=cert_esl("pca2011"), dbx=cert_esl("pca2011"))
        self.assertTrue(any("Windows cannot boot" in m for m in levels(r, "ACTION")))

    def test_windows_only_db_has_no_third_party_warning(self):
        r = run_vars(db=cert_esl("pca2011", "windowsuefica2023"))
        self.assertEqual(levels(r, "ACTION"), [])
        self.assertEqual(levels(r, "WARN"), [])

    def test_expiry_relative_to_now(self):
        before = run_vars(now=datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc), KEK=cert_esl("kek2011"))
        self.assertFalse(before["variables"]["KEK"]["certificates"][0]["expired"])
        after = run_vars(KEK=cert_esl("kek2011"))
        self.assertTrue(after["variables"]["KEK"]["certificates"][0]["expired"])


class ReferenceComparison(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ref = sb.load_dbx_reference(os.path.join(FIX, "dbx_info_msft_latest.json"))

    def test_reference_loaded(self):
        self.assertGreater(len(self.ref["hashes"]), 400)
        self.assertIn("580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d", self.ref["certs"])
        self.assertEqual(len(self.ref["svns"]), 3)

    def test_x64_dbx_against_reference(self):
        r = run_vars(ref=self.ref, dbx=fixture("dbx_x64.efiauth2"))
        ref = r["variables"]["dbx"]["reference"]
        self.assertEqual(ref["present"] + ref["missing"], ref["known_revoked_hashes"])
        self.assertGreater(ref["present"], 250)
        self.assertTrue(all(not s["current"] for s in ref["svns"]))

    def test_arch_filter(self):
        x64 = sb.load_dbx_reference(os.path.join(FIX, "dbx_info_msft_latest.json"), "x64")
        self.assertLess(len(x64["hashes"]), len(self.ref["hashes"]))
        _, esl, _ = sb.load_variable(fixture("DBXUpdate.bin"))
        hashes = set(sb.summarize(esl)["hashes"])
        self.assertEqual(len(hashes - set(x64["hashes"])), 0)

    def test_svns_current(self):
        dbx = sb.load_variable(fixture("dbx_SVN.efiauth2"))[1]
        r = run_vars(ref=self.ref, dbx=dbx)
        svns = {s["app"].split()[0]: s for s in r["variables"]["dbx"]["reference"]["svns"]}
        self.assertTrue(svns["cdboot.efi"]["current"])
        self.assertTrue(svns["wdsmgfw.efi"]["current"])


class CommandLine(unittest.TestCase):
    def _run(self, argv):
        out = io.StringIO()
        old = sys.stdout
        sys.stdout = out
        try:
            rc = sb.main(argv)
        finally:
            sys.stdout = old
        return rc, out.getvalue()

    def test_text_report_and_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            kek = os.path.join(d, "KEK.esl")
            with open(kek, "wb") as f:
                f.write(cert_esl("kek2011"))
            rc, out = self._run(["--kek", kek])
        self.assertEqual(rc, 1)
        self.assertIn("[ACTION] KEK lacks Microsoft Corporation KEK 2K CA 2023", out)

    def test_json_and_efivars_directory(self):
        with tempfile.TemporaryDirectory() as d:
            attrs = struct.pack("<I", 0x27)
            for name, guid, data in (("KEK", sb.EFI_GLOBAL_VARIABLE, cert_esl("kek2011", "kek2023")),
                                     ("db", sb.EFI_IMAGE_SECURITY_DATABASE, cert_esl("windowsuefica2023"))):
                with open(os.path.join(d, f"{name}-{guid}"), "wb") as f:
                    f.write(attrs + data)
            rc, out = self._run(["--efivars", d, "--json"])
        self.assertEqual(rc, 0)
        report = json.loads(out)
        self.assertEqual(report["variables"]["KEK"]["format"], "efivarfs")
        self.assertEqual(report["variables"]["db"]["certificates"][0]["microsoft"], "Windows UEFI CA 2023")


if __name__ == "__main__":
    unittest.main()
