""" FuzzyTargetGroup: a group of FuzzyTarget objects """

from massweb.targets.fuzzy_target import FuzzyTarget


class FuzzyTargetGroup(object):
    """ FuzzyTargetGroup type """

    def __init__(self, fuzzy_targets = None):
        """ Initialize FuzzyTargetGroup object
            fuzzy_targets   list of FuzzyTarget objects. Default None."""
        if not fuzzy_targets:
            fuzzy_targets = []
        self.fuzzy_targets = fuzzy_targets
        
    def add_targets(self, fuzzy_targets):
        """ Add an iterable of FuzzyTarget objects to this group.

            fuzzy_targets   iterable of FuzzyTarget objects.
        """
        if fuzzy_targets is None:
            raise TypeError("fuzzy_targets must be an iterable of FuzzyTarget objects")
        try:
            iterator = iter(fuzzy_targets)
        except TypeError:
            raise TypeError("fuzzy_targets must be an iterable of FuzzyTarget objects")
        fuzzy_targets_to_add = list(iterator)
        for fuzzy_target in fuzzy_targets_to_add:
            if not isinstance(fuzzy_target, FuzzyTarget):
                raise TypeError("fuzzy_target must be of type FuzzyTarget")
        self.fuzzy_targets.extend(fuzzy_targets_to_add)

    def add_target(self, fuzzy_target):
        """ add FuzzyTarget to the group
            fuzzy_target    ... guess ..."""
        if not isinstance(fuzzy_target, FuzzyTarget):
            raise TypeError("fuzzy_target must be of type FuzzyTarget")
        self.fuzzy_targets.append(fuzzy_target)
    
