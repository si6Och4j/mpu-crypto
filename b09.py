from b00_interface import eval_interface
from t21_rsa import rsa
from t22_elgamal import elgamal

interface_modules = [
    rsa,
    elgamal,
]

if __name__ == "__main__":
    eval_interface(interface_modules)