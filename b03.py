from b00_interface import eval_interface
from t08_matrix import matrix
from t09_playfair import playfair

interface_modules = [
    matrix,
    playfair,
]

if __name__ == "__main__":
    eval_interface(interface_modules)