from b00_interface import eval_interface
from t07_gost_r_34_12 import magma, kuznyechik
from t18_gost_28147_89 import gost_28147_89
from t19_aes import aes

interface_modules = [
    magma.ECB_wrap,
    gost_28147_89,
    aes,
    kuznyechik,
]

if __name__ == "__main__":
    eval_interface(interface_modules)