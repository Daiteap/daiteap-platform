import random
import string

def get_random_alphanumeric_string(length):
    letters_and_digits = string.ascii_letters + string.digits
    result_str = ''.join((random.choice(letters_and_digits) for i in range(length)))
    return(result_str)

def get_random_lowercase_hex_letters(length):
    hex_letters = 'abcdef'
    result_str = ''.join((random.choice(hex_letters) for i in range(length)))
    return(result_str)