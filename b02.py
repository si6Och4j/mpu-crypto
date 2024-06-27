from b00_interface import eval_interface
from t04_trithemius import trithemius
from t05_bellaso import bellaso
from t06_vigenere import vigenere
from t07_gost_r_34_12 import magma

interface_modules = [
    trithemius,
    bellaso,
    vigenere,
    magma.S_box,
]

if __name__ == "__main__":
    eval_interface(interface_modules)