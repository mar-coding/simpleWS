import random
import hashlib
def calc(a,ops,b):
    """Returns integer operation result from using : 'a','ops','b'"""
    if   ops == "+": return a+b
    elif ops == "-": return a-b
    elif ops == "*": return a*b
    elif ops == "/": return a//b   # integer division
    else: raise ValueError("Unsupported math operation")

def main():
    """
    Generates two random number and their correct
    multiply of two of them.
    Returns:
        number_a , number_b , correct_answer => list format
    """
    total = 1
    correct = 0
    min_range = random.randrange(1000000000,100000000000000)
    max_range = random.randrange(10000000000,10000000000000)
    if max_range != min_range and max_range > min_range:  
        nums = range(min_range,max_range)
    else:
        while max_range == min_range or max_range < min_range:
            min_range = random.randrange(1000000000,100000000000000)
            max_range = random.randrange(10000000000,10000000000000)
        nums = range(min_range,max_range)

    ops = "*"
    a,b = random.choices(nums,k=2)

    # calculate correct result
    corr = calc(a,ops,b)
    return a,b,corr

if __name__ == '__main__':
    main()