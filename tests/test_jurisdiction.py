"""Tests for jurisdiction profiles — pure Python dicts, no external deps."""
import unittest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from jurisdiction import get_profile, PROFILES
from jurisdiction.eu import PROFILE as EU
from jurisdiction.it import PROFILE as IT, AGID_TSA_ENDPOINTS
from jurisdiction.cz import PROFILE as CZ


REQUIRED_PROFILE_KEYS = (
    "id", "name", "tsa_url", "tsa_name", "hash_algorithms",
    "legal_references", "report_template", "notes",
)


class TestProfileStructure(unittest.TestCase):

    def _check_required_keys(self, profile: dict, label: str):
        for key in REQUIRED_PROFILE_KEYS:
            self.assertIn(key, profile, f"Profile '{label}' missing key: {key}")

    def test_eu_profile_keys(self):
        self._check_required_keys(EU, "eu")

    def test_it_profile_keys(self):
        self._check_required_keys(IT, "it")

    def test_cz_profile_keys(self):
        self._check_required_keys(CZ, "cz")


class TestGetProfile(unittest.TestCase):

    def test_eu_returns_eu_profile(self):
        p = get_profile("eu")
        self.assertEqual(p["id"], "eu")

    def test_it_returns_it_profile(self):
        p = get_profile("it")
        self.assertEqual(p["id"], "it")

    def test_cz_returns_cz_profile(self):
        p = get_profile("cz")
        self.assertEqual(p["id"], "cz")

    def test_case_insensitive(self):
        self.assertEqual(get_profile("EU")["id"], "eu")
        self.assertEqual(get_profile("It")["id"], "it")
        self.assertEqual(get_profile("CZ")["id"], "cz")

    def test_unknown_jurisdiction_raises_value_error(self):
        with self.assertRaises(ValueError):
            get_profile("xx")

    def test_unknown_message_mentions_valid_options(self):
        with self.assertRaises(ValueError) as ctx:
            get_profile("de")
        msg = str(ctx.exception)
        self.assertIn("eu", msg)
        self.assertIn("it", msg)
        self.assertIn("cz", msg)

    def test_all_profiles_registered(self):
        self.assertSetEqual(set(PROFILES.keys()), {"eu", "it", "cz"})


class TestEuProfile(unittest.TestCase):

    def test_tsa_url_is_freetsa(self):
        self.assertIn("freetsa.org", EU["tsa_url"])

    def test_hash_algorithms_include_sha256(self):
        self.assertIn("sha256", EU["hash_algorithms"])

    def test_legal_refs_mention_eidas(self):
        refs_text = " ".join(EU["legal_references"])
        self.assertIn("eIDAS", refs_text)

    def test_report_template_exists_as_string(self):
        self.assertTrue(EU["report_template"].endswith(".j2"))

    def test_notes_mention_eidas_article(self):
        self.assertIn("41", EU["notes"])


class TestItProfile(unittest.TestCase):

    def test_id_is_it(self):
        self.assertEqual(IT["id"], "it")

    def test_has_verbale_section(self):
        self.assertTrue(IT.get("verbale_section"))

    def test_extra_operator_fields_defined(self):
        self.assertIsInstance(IT["extra_operator_fields"], list)
        self.assertGreater(len(IT["extra_operator_fields"]), 0)

    def test_operator_field_has_key_and_label(self):
        for field in IT["extra_operator_fields"]:
            self.assertIn("key", field)
            self.assertIn("label", field)

    def test_legal_refs_mention_cad(self):
        refs_text = " ".join(IT["legal_references"])
        self.assertIn("CAD", refs_text)

    def test_report_template_is_italian(self):
        self.assertIn("it", IT["report_template"])

    def test_agid_tsa_list_not_empty(self):
        self.assertGreater(len(AGID_TSA_ENDPOINTS), 0)

    def test_agid_entries_are_name_url_tuples(self):
        for entry in AGID_TSA_ENDPOINTS:
            self.assertIsInstance(entry, tuple)
            self.assertEqual(len(entry), 2)
            name, url = entry
            self.assertIsInstance(name, str)
            self.assertTrue(url.startswith("http"))


class TestCzProfile(unittest.TestCase):

    def test_id_is_cz(self):
        self.assertEqual(CZ["id"], "cz")

    def test_legal_refs_mention_czech_act(self):
        refs_text = " ".join(CZ["legal_references"])
        self.assertIn("297/2016", refs_text)

    def test_report_template_is_czech(self):
        self.assertIn("cz", CZ["report_template"])

    def test_notes_mention_eidas_article(self):
        self.assertIn("41", CZ["notes"])

    def test_hash_algorithms_include_sha256(self):
        self.assertIn("sha256", CZ["hash_algorithms"])


if __name__ == "__main__":
    unittest.main()
