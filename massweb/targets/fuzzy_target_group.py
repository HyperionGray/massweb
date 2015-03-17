""" FuzzyTargetGroup: a group of FuzzyTarget objects """


class FuzzyTargetGroup(object):
    """ FuzzyTargetGroup type """

    def __init__(self, fuzzy_targets = None):
        """ Initialize FuzzyTargetGroup object
            fuzzy_targets   list of FuzzyTarget objects. Default None."""
        if not fuzzy_targets:
            fuzzy_targets = []
        self.fuzzy_targets = fuzzy_targets
        
    #FIXME: create a method add_targets() that adds a list of Targets at once
    #  See PNKTHR-59

    def add_target(self, fuzzy_target):
        """ add FuzzyTarget to the group
            fuzzy_target    ... guess ..."""
        self.fuzzy_targets.append(fuzzy_target)
    
