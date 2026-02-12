import unittest

from palo_alto_ops import _extract_xml_value, _members_xml, _split_csv, _xml_escape


class TestHelpers(unittest.TestCase):
    def test_xml_escape(self):
        self.assertEqual(_xml_escape("a&b<'\""), "a&amp;b&lt;&apos;&quot;")

    def test_members_xml_defaults_to_any(self):
        self.assertEqual(_members_xml([]), "<member>any</member>")

    def test_members_xml_builds_members(self):
        self.assertEqual(
            _members_xml(["trust", "untrust"]),
            "<member>trust</member><member>untrust</member>",
        )

    def test_extract_xml_value(self):
        self.assertEqual(_extract_xml_value("<response><key>abc</key></response>", "key"), "abc")
        self.assertIsNone(_extract_xml_value("<response></response>", "key"))

    def test_split_csv(self):
        self.assertEqual(_split_csv("a,b , c"), ["a", "b", "c"])


if __name__ == "__main__":
    unittest.main()
