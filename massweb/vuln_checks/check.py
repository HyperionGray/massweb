""" Check class prototype """


class Check(object):
    """ Check class prototype """

    def check(self, content: str) -> bool:
        """Check the response content for evidence of a vulnerability.

        content     str of response body to check.

        returns     True if a vulnerability indicator is found, False otherwise.
        raises      NotImplementedError when called on the base class directly.
        """
        raise NotImplementedError("Check.check() is not implemented in this class.")
