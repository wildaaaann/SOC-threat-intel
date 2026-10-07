import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ioc_extract import extract_iocs, first_public_ip, pick_primary, refang  # noqa: E402

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def values(iocs, kind=None):
    return [i["value"] for i in iocs if kind is None or i["type"] == kind]


class ExtractIocsTest(unittest.TestCase):
    def test_mixed_alert(self):
        text = f"Url: hxxps://evil[.]example[.]com/a/b.php Src: 8.8.8.8 Internal: 10.0.0.5 File: {MD5}"
        iocs = extract_iocs(text)
        self.assertEqual(values(iocs, "domain"), ["evil.example.com"])
        self.assertEqual(values(iocs, "ip"), ["8.8.8.8", "10.0.0.5"])
        self.assertEqual(values(iocs, "md5"), [MD5])
        public = {i["value"]: i["public"] for i in iocs if i["type"] == "ip"}
        self.assertTrue(public["8.8.8.8"])
        self.assertFalse(public["10.0.0.5"])

    def test_sha256_is_not_split_into_shorter_hashes(self):
        iocs = extract_iocs(f"hash={SHA256}")
        self.assertEqual([(i["type"], i["value"]) for i in iocs], [("sha256", SHA256)])

    def test_email_gives_domain_not_local_part(self):
        iocs = extract_iocs("From john.doe@phish-corp.com to admin")
        self.assertEqual(values(iocs, "domain"), ["phish-corp.com"])

    def test_file_names_are_not_domains(self):
        iocs = extract_iocs("Process payload.exe wrote C:\\temp\\run.ps1 and app.py")
        self.assertEqual(iocs, [])

    def test_url_path_is_not_a_domain(self):
        iocs = extract_iocs("GET https://cdn.example.org/static/lib.min.js")
        self.assertEqual(values(iocs, "domain"), ["cdn.example.org"])

    def test_dedup_and_case(self):
        iocs = extract_iocs("Evil.COM evil.com 1.2.3.4 1.2.3.4")
        self.assertEqual(values(iocs), ["evil.com", "1.2.3.4"])

    def test_version_numbers_are_not_ips(self):
        self.assertEqual(extract_iocs("agent 4.7.10.2.1 build"), [])

    def test_empty(self):
        self.assertEqual(extract_iocs(""), [])
        self.assertEqual(extract_iocs("   "), [])
        self.assertEqual(extract_iocs(None), [])


class PickPrimaryTest(unittest.TestCase):
    def test_hash_beats_domain_beats_ip(self):
        iocs = extract_iocs(f"1.1.1.1 evil.com {MD5}")
        self.assertEqual(pick_primary(iocs), MD5)
        self.assertEqual(pick_primary(extract_iocs("1.1.1.1 evil.com")), "evil.com")
        self.assertEqual(pick_primary(extract_iocs("1.1.1.1")), "1.1.1.1")

    def test_private_ip_is_never_primary(self):
        self.assertIsNone(pick_primary(extract_iocs("src 192.168.1.20")))

    def test_first_public_ip(self):
        iocs = extract_iocs("10.1.1.1 then 9.9.9.9 then 8.8.8.8")
        self.assertEqual(first_public_ip(iocs), "9.9.9.9")
        self.assertIsNone(first_public_ip(extract_iocs("10.1.1.1")))


class RefangTest(unittest.TestCase):
    def test_refang(self):
        self.assertEqual(refang("hxxps[://]evil[.]com"), "https://evil.com")


if __name__ == "__main__":
    unittest.main()
