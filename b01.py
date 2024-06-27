from b00_interface import eval_interface
from t01_atbash import atbash
from t02_polybius_square import polybius_square
from t03_caesar import caesar

interface_modules = [
    atbash,
    polybius_square,
    caesar,
]

if __name__ == "__main__":
    eval_interface(interface_modules)
