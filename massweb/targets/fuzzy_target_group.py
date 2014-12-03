class FuzzyTargetGroup(object):
    def __init__(self, fuzzy_targets = None):

        if not fuzzy_targets:
            fuzzy_targets = []

        self.fuzzy_targets = fuzzy_targets
        
    def add_target(self, fuzzy_target):
        
        self.fuzzy_targets.append(fuzzy_target)
    