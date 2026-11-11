"""The chart generator must produce well-formed SVG whose bar totals match the data."""
import json
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from pqtls.plot import SIGS, GROUPS, segments, svg

RESULTS = Path(__file__).resolve().parent.parent / "results" / "windows-openssl-3.5.6.json"


class Plot(unittest.TestCase):
    def setUp(self) -> None:
        data = json.loads(RESULTS.read_text(encoding="utf-8"))
        self.results = {(r["signature"], r["group"]): r for r in data["results"]}

    def test_segments_add_up_to_bytes_read(self) -> None:
        for key, r in self.results.items():
            with self.subTest(key=key):
                self.assertEqual(sum(segments(r)), r["handshake"]["bytes_read"])

    def test_svg_is_well_formed_in_both_themes(self) -> None:
        for theme in ("light", "dark"):
            with self.subTest(theme=theme):
                root = ET.fromstring(svg(self.results, theme))
                titles = [t.text for t in root.iter("{http://www.w3.org/2000/svg}title")]
                # 4 segments per bar, one bar per (signature, group).
                self.assertEqual(len(titles), 4 * len(SIGS) * len(GROUPS))


if __name__ == "__main__":
    unittest.main()
