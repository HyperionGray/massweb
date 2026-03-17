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
        """ Add multiple FuzzyTargets to the group in order.

            fuzzy_targets    iterable of FuzzyTarget objects.
        """
        if not isinstance(fuzzy_targets, (list, tuple)):
            raise TypeError("fuzzy_targets must be a list or tuple")
        for fuzzy_target in fuzzy_targets:
            self.add_target(fuzzy_target)
    
