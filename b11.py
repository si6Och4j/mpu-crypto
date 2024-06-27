from b00_interface import eval_interface
from t28_diffie_hellman_ke import diffie_hellman_ke

interface_modules = [
    diffie_hellman_ke,
]

if __name__ == "__main__":
    eval_interface(interface_modules)