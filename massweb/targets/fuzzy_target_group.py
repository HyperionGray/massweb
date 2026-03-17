""" FuzzyTargetGroup: a group of FuzzyTarget objects """


class FuzzyTargetGroup(object):
    """ FuzzyTargetGroup type """

    def __init__(self, fuzzy_targets = None):
        """ Initialize FuzzyTargetGroup object
            fuzzy_targets   list of FuzzyTarget objects. Default None."""
        if not fuzzy_targets:
            fuzzy_targets = []
        self.fuzzy_targets = fuzzy_targets
        
    def add_target(self, fuzzy_target):
        """ add FuzzyTarget to the group
            fuzzy_target    ... guess ..."""
        self.fuzzy_targets.append(fuzzy_target)

    def add_targets(self, fuzzy_targets):
        """Add an iterable of fuzzy targets to the group."""
        if fuzzy_targets is None:
            raise TypeError("fuzzy_targets must be an iterable, not None")
        for fuzzy_target in fuzzy_targets:
            self.add_target(fuzzy_target)

