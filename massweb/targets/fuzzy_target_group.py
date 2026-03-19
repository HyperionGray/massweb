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

    def add_targets(self, fuzzy_target_list):
        """ Add a list of FuzzyTarget objects to the group.

        fuzzy_target_list   list of FuzzyTarget objects to add.
        """
        self.fuzzy_targets.extend(fuzzy_target_list)
    
