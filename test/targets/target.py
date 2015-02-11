""" Target type/prototype """

import unittest
from massweb.targets.target import Target


class TestTarget(unittest.TestCase):
    """ Target prototype:
        contains the url, request type, and data (POST request payload as dict)
    """

    def test_eq(self):
        # fail if not:
        #   isinstance(other, Target):
        #   self.assertRaise(TypeError)
        #   self.url == other.url and
        #   self.ttype == other.ttype
        #   self.data == other.data
        pass

    def test_hash(self):
        # check output
        #   hash((self.url, self.ttype, str(self.data)))
        pass

    def test_unicode(self):
        # check output
        # self.url
        pass

    def test_str(self):
        # unicode(self).encode('utf-8', 'replace')
        pass

    def test_init(self):
        # url, data=None, ttype="get"):
        # fail if not:
        #   isinstance(url, unicode):
        #       self.assertRaise(TypeError)
        #   self.url = url
        #   self.ttype = ttype
        #   self.data = data
        pass

    def test_domain(self):
        # check output only
        pass

    def test_path(self):
        # check output only
        pass

    def test_full(self):
        target_1 = Target(u"http://www.hyperiongray.com/", ttype="post",
                          data={"k1": "v1"})
        target_2 = Target(u"http://www.hyperiongray.com/", ttype="post",
                          data={"k1": "v2"})
        target_3 = Target(u"http://www.hyperiongray.com/", ttype="post",
                          data={"k1": "v1"})
        #FIXME: original test code had target_1 == target_2 
        self.assertNotEqual(target_1, target_2)
        self.assertEqual(target_1, target_3)


if __name__ == '__main__':
    unittest.main()
