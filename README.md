**Помимо условий [лицензии](LICENSE.txt), автор также не несёт никакой ответственности за то,
на сколько сильно преподаватель будет избивать студента на экзамене за бездумное копирование.**

[Основной репозиторий](https://gitflic.ru/project/consensus/mpu-crypto)|[Блок-схемы](Схемы.drawio) | [Методичка ЛАБКРИПТ](https://studylib.net/doc/25415492/lab-kript-)

Реализованы следующие алгоритмы:
- Блок А: ШИФРЫ ОДНОЗНАЧНОЙ ЗАМЕНЫ
  - [Шифр простой замены АТБАШ](t01_atbash.py)
  - [Шифр Цензаря](t03_caesar.py)
  - [Квадрат Полибия](t02_polybius_square.py)
- Блок В: ШИФРЫ МНОГОЗНАЧНОЙ ЗАМЕНЫ
  - [Шифр Тритемия](t04_trithemius.py)
  - [Шифр Белазо](t05_bellaso.py)
  - [Шифр Виженера](t06_vigenere.py)
  - [S-блок замены ГОСТ Р 34.12-2015 («МАГМА»)](t07_gost_r_34_12.py#L109)
- Блок С: ШИФРЫ БЛОЧНОЙ ЗАМЕНЫ
  - [Матричный шифр](t08_matrix.py)
  - [Шифр Плэйфера – шифр биграммной замены](t09_playfair.py)
- Блок D: ШИФРЫ ПЕРЕСТАНОВКИ
  - [Вертикальная перестановка](t10_vertical_shuffle.py)
  - [Решетка Кардано](t11_cardan_grille.py)
  - > Реализована генерация решётки
  - [Перестановка в комбинационных шифрах](t07_gost_r_34_12.py#L62)
- Блок E: ШИФРЫ ГАММИРОВАНИЯ
  - [Одноразовый блокнот К.Шеннона](t13_one_time_pad.py)
  - > Реализована генерация значений
  - [ГОСТ Р 34.13-2015 (ГОСТ Р 34.12-2015 «Магма»)](t07_gost_r_34_12.py#L257)
  - > Для ГОСТ 28147-89 сами делайте
- Блок F: ПОТОЧНЫЕ ШИФРЫ
  - [А5/1](t15_a5_1.py)
  - [А5/2](t16_a5_2.py)
  - > Документации нет, так как алгоритмы *абсолютно проприетарные*, по этому trust me bro
- Блок G: КОМБИНАЦИОННЫЕ ШИФРЫ
  - [МАГМА](t07_gost_r_34_12.py#L201)
  - > Тестирование по значениям из стандарта проходит
  - [ГОСТ 28147-89](t18_gost_28147_89.py)
  - > S-Box в стандарте отсутствует, но с тем, который есть в ГОСТ Р 34.11-94, тестирование по значениям проходит
  - [AES](t19_aes.py)
  - > Тестирование по значениям из стандарта проходит
  - [КУЗНЕЧИК](t07_gost_r_34_12.py#L348)
  - > Тестирование по значениям из стандарта проходит
- БЛОК H: АСИММЕТРИЧНЫЕ ШИФРЫ
- > Генерация ключей реализована
  - [RSA](t21_rsa.py)
  - [ElGamal](t22_elgamal.py)
  - [ElGamal ECC (ECC – С ИСПОЛЬЗОВАНИЕМ АБСЦИССЫ ТОЧКИ)](t23_ecc_elgamal.py)
- БЛОК I: АЛГОРИТМЫ ЦИФРОВЫХ ПОДПИСЕЙ
  - [RSA](t21_rsa.py)
  - [ElGamal](t22_elgamal.py)
- БЛОК J: СТАНДАРТЫ ЦИФРОВЫХ ПОДПИСЕЙ
  - [ГОСТ Р 34.10-94](t26_gost_34_10.py#L8)
  - > Генерация ключей реализована не до конца ([Генератор](t26_gost_34_10_94_lcg.py))
  - [ГОСТ Р 34.10-2012](t27t_gost_34_10_2012.py)
- БЛОК K: ОБМЕН КЛЮЧАМИ
  - [ОБМЕН КЛЮЧАМИ ПО ДИФФИ-ХЕЛЛМАНУ](t28_diffie_hellman_ke.py)
