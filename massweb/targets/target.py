""" Target type/prototype """

class Target(object):
    """ Target prototype:
        contains the url, request type, and ?data?"""
        #FIXME: wtf is data ^

    def __eq__(self, other):
        """ Test whether this object and another Target object are equal based
            on the url, request type and ?data?
            other   Target object to compare to this object."""
        if not isinstance(other, Target):
            raise TypeError("Must provide Target or subclass of Target for comparison.")
        return (self.url == other.url and
                self.ttype == other.ttype and
                self.data == other.data)

    def __hash__(self):
        """ Returns a hash of the url, request type, and ?data? """
        return hash((self.url, self.ttype, str(self.data)))

    def __unicode__(self):
        """ Returns the URL as a unicode object """
        return self.url

    def __str__(self):
        """ Returns the URL as a UTF-8 str. """
        return unicode(self).encode('utf-8', 'replace')

    def __init__(self, url, data=None, ttype="get"):
        """ Initialize a Target?:
            url     unicode object containing the location of the target.
            data    ?data?
            ttype   HTTP request type (get,post). Default "get". """
        #FIXME: why so picky about unicode?
        if not isinstance(url, unicode):
            raise TypeError("URL input must be unicode, not string")
        self.url = url
        self.ttype = ttype
        self.data = data



#FIXME: put in unittest
"""
def test__eq__(self):
    t1 = Target(u"http://www.hyperiongray.com/", ttype = "post", data = {"k1" : "v1"})
    t2 = Target(u"http://www.hyperiongray.com/", ttype = "post", data = {"k1" : "v2"}) 
    l = [t1]
    self.assertEqual(t1, t2)
"""

