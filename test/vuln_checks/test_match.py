""" Test Helper functions for matching parts of strings """
#FIXME: Add comments
import unittest

from massweb.vuln_checks import match


class TestMatchMatchString(unittest.TestCase):

    def setUp(self):
        self.term = "alert!!"
        self.match_string_true = [x % self.term for x in ['%s', ' %s ', '\0%s\0']]
        self.match_string_false = ['', 'mary had a little lamb']

    def test_match_string(self):
        for str_in in self.match_string_true:
            self.assertTrue(match.match_string(str_in, self.term))
        for str_in in self.match_string_false:
            self.assertFalse(match.match_string(str_in, self.term))


class TestMatchMatchStrings(unittest.TestCase):

    def setUp(self):
        self.match_strings_terms = ['term0', 'term1!!', ' hello#', '\0']
        self.match_strings_true = [' rwfwref ewfwaef wae fterm0', '\0\0term1!!', '\' hello#*', '\1\0\5']
        self.match_strings_false = ['term', ' term1 ', ' hello', '\1']

    def test_match_strings(self):
        for str_in in self.match_strings_true:
            self.assertTrue(match.match_strings(str_in, self.match_strings_terms))
        for str_in in self.match_strings_false:
            self.assertFalse(match.match_strings(str_in, self.match_strings_terms))


class TestMatchParseMatch(unittest.TestCase):

    def setUp(self):
        self.tag = "script"
        self.term = "alert!!"
        parse_match_true = ['<html><head><title>script in head</title><%(tag)s>%(term)s</%(tag)s><head></html>', '<html><head><title>script in body</title></head><body><%(tag)s>%(term)s</%(tag)s></body></html>', '<html><head><title>script with attributes</title><%(tag)s class="someclass" id="someid">%(term)s</%(tag)s><head></html>']
        self.parse_match_false = ['', '<a>%s</a>' % self.term, self.term]
        self.parse_match_true = [x % {'term': self.term, 'tag': self.tag} for x in parse_match_true]

    def test_parse_match(self):
        for str_in in self.parse_match_true:
            self.assertTrue(match.parse_match(str_in, self.tag, self.term))
        for str_in in self.parse_match_false:
            self.assertFalse(match.parse_match(str_in, self.tag, self.term))
            


if __name__ == "__main__":
    unittest.main()
