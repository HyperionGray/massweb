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

    def add_targets(self, fuzzy_targets, dedupe=False):
        """Add multiple targets to the group.

        fuzzy_targets   iterable of targets to add.
        dedupe          if True, skip targets already present in the group.

        Return:
            Number of targets that were added.
        """
        if fuzzy_targets is None:
            raise TypeError("fuzzy_targets must be an iterable, not None")

        try:
            targets_iter = iter(fuzzy_targets)
        except TypeError:
            raise TypeError("fuzzy_targets must be an iterable")

        added = 0
        for fuzzy_target in targets_iter:
            if dedupe and fuzzy_target in self.fuzzy_targets:
                continue
            self.add_target(fuzzy_target)
            added += 1
        return added

