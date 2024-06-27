from b00_interface import eval_interface
from t26_gost_34_10 import gost_34_10

interface_modules = [
    gost_34_10.s94,
    gost_34_10.s2012,
]

if __name__ == "__main__":
    eval_interface(interface_modules)