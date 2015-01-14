import string


def expand_cases(test_input):
    """ assumes all lower input """
    # add Perword Caps
    test_input += [string.capwords(x) for x in test_input]
    # add OPPOSITE cASES
    test_input += [x.swapcase() for x in test_input]
    return test_input
