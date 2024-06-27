from b00_interface import eval_interface
from t21_rsa import rsa
from t22_elgamal import elgamal
from t23_ecc_elgamal import ecc_elgamal

interface_modules = [
    rsa,
    elgamal,
    ecc_elgamal,
]

if __name__ == "__main__":
    eval_interface(interface_modules)