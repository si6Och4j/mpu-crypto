from t11_cardan_grille import cardan_grille
from b00_interface import eval_interface
from t10_vertical_shuffle import vertical_shuffle
from t07t_magma_s_block import magma

interface_modules = [
    vertical_shuffle,
    cardan_grille,
    magma.P_box,
]

if __name__ == "__main__":
    eval_interface(interface_modules)
