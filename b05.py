from b00_interface import eval_interface
from t13_one_time_pad import one_time_pad
from t07_gost_r_34_12 import magma

interface_modules = [
    one_time_pad,
    magma.CTR_wrap,
]

if __name__ == "__main__":
    eval_interface(interface_modules)