
import unittest
from massweb.vuln_checks import xss

class TestXSSCheck(unittest.TestCase):

    def setUp(self):
        term = "alert(31337)"
        true = ['<html><head><title>script in head</title><script>%s</script><head></html>',
                '<html><head><title>script in body</title></head><body><script>%s</script></body></html>',
                '<html><head><title>script with attributes</title><script class="someclass" id="someid">%s</script><head></html>']
        self.false = ['', '<a>%s</a>' % term, term]
        self.true = [x % term for x in true]

    def test_xss_check(self):
        x = xss.XSSCheck()
        for t in self.true:
            self.assertTrue(x.check(t))
        for f in self.false:
            self.assertFalse(x.check(f))


if __name__ == "__main__":
    unittest.main()

