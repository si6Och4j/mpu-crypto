import os
import matplotlib.pyplot as plt

class share:
    alphabet_ru32 = "абвгдежзийклмнопрстуфхцчшщъыьэюя"

def plot(instance, name=None):
    plot_data = {}
    total = 0

    data = instance.get_data()
    for i in instance:
        if i in plot_data:
            continue

        cnt = data.count(i)
        plot_data[i] = cnt
        total += cnt

    v_max = 0
    result = {}
    for k, v in plot_data.items():
        if v > v_max:
            v_max = v
        result[k] = round(v / total, 3)

    print(result)

    if name is None:
        filename = os.path.basename(__file__)
        name = filename[:len(filename) - 3]


    plt.bar(*zip(*result.items()))
    plt.title(f'Гистограмма частот встречаемости {name}')
    plt.ylabel('Частота')
    plt.xlabel('Шифрвеличина')

    print(f'{name}-plot.png')
    plt.savefig(f'{name}-plot.png')
    #plt.show()
    plt.clf()


class S_iter():
    def __init__(self, data, iter_data):
        self.data = data
        self.iter_data = iter_data

    def __iter__(self):
        for d in self.iter_data:
            yield d

    def get_data(self):
        return self.data


class N_iter:
    def __init__(self, data):
        self.data = data

    def __iter__(self):
        for d in self.data.split(' '):
            yield d

    def get_data(self):
        return self.data.split(' ')

class F_iter:
    def __init__(self, data):
        self.data = data

    def __iter__(self):
        for d in self.data:
            yield d

    def get_data(self):
        return self.data


if __name__ == "__main__":
    #cips = {
    #	'original': S_iter('сынсапожникавсегдаходитбосикомтчк', share.alphabet_ru32),
    #	'atbash': S_iter('одтоярсщтчхяэоъьыяксычнюсочхсуних', share.alphabet_ru32),
    #	'polybius_square': N_iter('36 54 32 36 11 34 33 21 32 23 25 11 13 36 16 14 15 11 44 33 15 23 41 12 33 36 23 25 33 31 41 46 25'),
    #	'caesar': S_iter('фюрфгтсйрлнгефижзгшсзлхдслнспхън', share.alphabet_ru32),
    #	'trithemius': S_iter('сьпфдффнхсфлоюутфсзбшэишжквекйрцк', share.alphabet_ru32),
    #	'bellaso': S_iter('фйцхатьпсинолхежтйщозцыеофцутмхеу', share.alphabet_ru32),
    #	'vigenere_1': S_iter('шмиюспэфухтквуциздхгтмъупящтшъюйб', share.alphabet_ru32),
    #	'cardan_grille': S_iter('тсучкпмхгчыаданхсабодпрдиоыцтжофбнтбоинкмкигагобсуихаковсмые', share.alphabet_ru32),
    #	'route_shuffle': S_iter('сжеиоынгтмниубтскаочаахскпвоибосдку', share.alphabet_ru32),
    #	'vertical_shuffle': S_iter('ыжсосчсовхотакдтосигикннедикпаабм', share.alphabet_ru32),
    #	'matrix': N_iter('60 160 154 66 108 83 57 103 91 12 68 38 21 57 84 07 31 20 37 145 70 15 85 67 42 120 99 50 98 110 52 154 127'),
    #	'vigenere_2': S_iter('аыищщицьйсыыэоуцъъпэбйыькыгнызщръ', share.alphabet_ru32),
    #	'playfair': S_iter('ояргуиудпкимзмнгбоыдблщигаклгофшфь', share.alphabet_ru32),
    #	'rsa': N_iter('06 19 20 06 01 25 27 28 20 15 11 01 09 06 30 16 14 01 22 27 14 15 13 29 27 06 15 11 27 07 13 18 11'),
    #	'elgamal': N_iter('05 28 17 13 18 34 02 10 13 32 22 32 32 26 20 06 19 03 35 32 24 18 15 35 05 11 17 11 18 06 02 02 13 36 22 26 32 28 20 10 19 05'),
    #	'one_time_pad': S_iter('хфяашммябчьщвцлкрчзлмгафттояючижо', share.alphabet_ru32),
    #}
    cips = {
        'original': S_iter('выпущенноесловоикаменьнеимеютвозврататчк', share.alphabet_ru32),
        'atbash': S_iter('эдрмжъттсъофсэсчхяуътгтъчуъбнэсшэпяняних', share.alphabet_ru32),
        'polybius_square': N_iter('13 54 34 42 52 16 32 32 33 16 36 26 33 13 33 23 25 11 31 16 32 55 32 16 23 31 16 61 41 13 33 22 13 35 11 41 11 41 46 25'),
        'caesar': S_iter('еютцьиррсифосеслнгпирярилпибхескеугхгхън', share.alphabet_ru32),
        'trithemius': S_iter('вьсцэкуфцоыцъпьчъсюшбсгьаеящоямжвсвхдчэс', share.alphabet_ru32),
        'bellaso': S_iter('оггябщщхвсщяъквфтфшнбихщффщкъцъпцьижмълц', share.alphabet_ru32),
        'vigenere_1': S_iter('мэквмютъыуцьщррцткмстййтнфсгрфрхйтртттйб', share.alphabet_ru32),
        'cardan_grille': S_iter('ивукамфмовырзвпрущеатенуаньитнначоеюкеишясмеэюйоатхрлацовчво', share.alphabet_ru32),
        'route_shuffle': S_iter('вноьттыоинвапекеотусаизчщлммвкеоеерфнвнюаа', share.alphabet_ru32),
        'vertical_shuffle': S_iter('весинмотынлкьезащеоеивакпноанювтуовметрч', share.alphabet_ru32),
        'matrix': N_iter('367 257 55 296 246 206 245 201 140 252 186 72 147 138 138 115 98 92 165 145 123 197 201 275 195 153 98 223 222 298 108 108 143 159 152 154 340 237 28 298 229 120'),
        'vigenere_2': S_iter('ьчжщтчдсядхаорюжррьбокчьдрхуезхьюооаатйу', share.alphabet_ru32),
        'playfair': S_iter('мзлияазхгхашмпгмуцвжгцэудцрвьчгмвмжесбфшзс', share.alphabet_ru32),
        'rsa': N_iter('27 7 4 14 20 18 5 5 9 18 24 12 9 27 9 3 11 1 19 18 5 2 5 18 3 19 18 25 28 27 9 17 27 29 1 28 1 28 30 11'),
        'elgamal': N_iter('18 37 19 7 29 35 19 5 29 30 12 40 30 9 29 36 12 14 26 38 19 26 33 33 29 14 19 33 5 25 29 17 26 41 5 16 30 36 18 31 12 36 30 34 26 17 30 10 33 14 18 17 5 10 5 23 18 5 34 12 34 17 12 39 33 19 30 14 33 35 5 3 26 35 29 12 19 6 12 16'),
        'one_time_pad': S_iter('блощжйфгхндйщжыкщабчвадыяфаихцлщбаэьыюва', share.alphabet_ru32),
    }
    #cips = {
    #	'original': S_iter('ктообжегсянасупезптдуетинахолоднуюрыбутчк', share.alphabet_ru32),
    #	'atbash': S_iter('хнссю щъьоа тяомр ъшрны мънчт яксфс ытмбп дюмни х', share.alphabet_ru32),
    #	'polybius_square': N_iter('25 41 33 33 12 21 16 14 36 62 32 11 36 42 34 16 22 34 41 15 42 16 41 23 32 11 44 33 26 33 15 32 42 61 35 54 12 42 41 46 25'),
    #	'caesar': S_iter('нхссдйижфвргфцтиктхзцихлргшсосзрцбуюдцхън', share.alphabet_ru32),
    #	'trithemius': S_iter('курселлкщичлэаэфчадчзъияещпйзлвмуятюешшют', share.alphabet_ru32),
    #	'bellaso': S_iter('ыаыяпуцсюрынвбьцхьгтацахюовящыхыапюитбяиш', share.alphabet_ru32),
    #	'vigenere_1': S_iter('хдььвмкжвюъавжюкоюдижкдръакьцьиъжьацвждох', share.alphabet_ru32),
    #	#'cardan_grille': S_iter('ивукамфмовырзвпрущеатенуаньитнначоеюкеишясмеэюйоатхрлацовчво', share.alphabet_ru32),
    #	'route_shuffle': S_iter('кгпельтсетобоязидуонпннтбатаучеууор', share.alphabet_ru32),
    #	#'vertical_shuffle': S_iter('весинмотынлкьузащеоеивакпноанювтуовметрч', share.alphabet_ru32),
    #	#'matrix': N_iter('367 257 55 296 246 206 245 201 140 252 186 72 147 138 138 115 98 92 165 145 123 197 201 275 195 153 98 223 222 298 108 108 143 159 152 154 340 237 28 298 229 120'),
    #	#'vigenere_2': S_iter('ьчжщтчдсядхаорюжррьбокчьдрхуезхьюооаатйу', share.alphabet_ru32),
    #	#'playfair': S_iter('мзлияазхгхашмпгмуцвжгцэудцрвьчгмвмжесбфшзс', share.alphabet_ru32),
    #	#'rsa': N_iter('27 7 4 14 20 18 5 5 9 18 24 12 9 27 9 3 11 1 19 18 5 2 5 18 3 19 18 25 28 27 9 17 27 29 1 28 1 28 30 11'),
    #	#'elgamal': N_iter('18 37 19 7 29 35 19 5 29 30 12 40 30 9 29 36 12 14 26 38 19 26 33 33 29 14 19 33 5 25 29 17 26 41 5 16 30 36 18 31 12 36 30 34 26 17 30 10 33 14 18 17 5 10 5 23 18 5 34 12 34 17 12 39 33 19 30 14 33 35 5 3 26 35 29 12 19 6 12 16'),
    #	'one_time_pad': S_iter('блощжйфгхндйщжыкщабчвадыяфаихцлщбаэьыюва', share.alphabet_ru32),
    #}

    for name, instance in cips.items():
        plot(instance, name)
