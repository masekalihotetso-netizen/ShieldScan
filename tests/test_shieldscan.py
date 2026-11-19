import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shieldscan.scanner import scan_file, UnsupportedFile  # noqa: E402
from shieldscan.utils import sha256_file  # noqa: E402

S = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


def p(n):
    return os.path.join(S, n)


class Detector(unittest.TestCase):
    def test_phishing_email_is_high(self):
        self.assertEqual(scan_file(p("phishing_ceo_fraud.eml"), "phishing_ceo_fraud.eml")["level"], "High")

    def test_legit_email_is_low(self):
        self.assertEqual(scan_file(p("legit_minutes.eml"), "legit_minutes.eml")["level"], "Low")

    def test_natural_photo_low(self):
        self.assertEqual(scan_file(p("photo_real.jpg"), "photo_real.jpg")["level"], "Low")

    def test_synthetic_voice_flagged_more_than_natural(self):
        a = scan_file(p("voice_synthetic.wav"), "a.wav")["score"]
        b = scan_file(p("voice_natural.wav"), "b.wav")["score"]
        self.assertGreater(a, b + 30)

    def test_all_supported_types_do_not_corrupt(self):
        for n in ("phishing_ceo_fraud.eml", "photo_real.jpg", "image_synthetic.png", "voice_natural.wav", "clip_sample.mp4"):
            before = sha256_file(p(n))
            r = scan_file(p(n), n)
            self.assertTrue(r["integrity"]["unchanged"], n)
            self.assertEqual(before, sha256_file(p(n)), n)

    def test_disguised_file_is_flagged(self):
        d = tempfile.mkdtemp()
        fake = os.path.join(d, "invoice.txt")
        with open(p("photo_real.jpg"), "rb") as f, open(fake, "wb") as g:
            g.write(f.read())
        r = scan_file(fake, "invoice.txt")
        self.assertEqual(r["kind"], "image")
        self.assertTrue(any("disguise" in e["text"] for e in r["evidence"]))

    def test_unsupported_binary_rejected(self):
        f = os.path.join(tempfile.mkdtemp(), "x.bin")
        open(f, "wb").write(bytes(range(256)) * 20)
        with self.assertRaises(UnsupportedFile):
            scan_file(f, "x.bin")

    def test_corrupt_media_is_handled(self):
        f = os.path.join(tempfile.mkdtemp(), "broken.mp4")
        open(f, "wb").write(b"\x00\x00\x00\x18ftypmp42" + os.urandom(2000))
        r = scan_file(f, "broken.mp4")
        self.assertTrue(r["integrity"]["unchanged"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
