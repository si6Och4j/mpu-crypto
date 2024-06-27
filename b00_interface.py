import sys
import share
from print_buffer import LBuffer

supported_capabilities = {
    'enc': 'Зашифровать',
    'dec': 'Расшифровать',
    'sig': 'Подписать',
    'ver': 'Проверить',
    'kec': 'Начать обмен ключами',
    'kee': 'Совершить обмен ключами',
    'kyg': 'Создать ключ'
}

def eval_test_kec(cls, control, global_data):
    _, _, key = control

    key_s, vals = cls._MODULE_CAPABILITIES['kec'](
        key
    )

    print(f'Алгоритм: {cls._MODULE_NAME}')
    print(f'Общие значения: {key}')
    print(f'Секретное значение A: {key_s}')
    print(f'Послка A: {vals}')

    global_data['kec_data'] = vals
    global_data['kec_key'] = key_s

def eval_test_kee(cls, control, global_data):
    _, _, key = control

    if not 'kec_data' in global_data:
        print('Не могу произвести обмен ключами')
        return

    key_s, vals = cls._MODULE_CAPABILITIES['kec'](
        key
    )
    print(f'Общие значения: {key}')
    print(f'Секретное значение B: {key_s}')
    print(f'Послка B: {vals}')
    print()

    k = cls._MODULE_CAPABILITIES['kee'](
        key,
        vals,
        global_data['kec_key']
    )
    print('Общий ключ для A: ')
    print(k)

    k = cls._MODULE_CAPABILITIES['kee'](
        key,
        global_data['kec_data'],
        key_s
    )
    print('Общий ключ для B: ')
    print(k)

def eval_test_enc(cls, control, global_data):
    msg, c_vals, key = control

    print(f'Алгоритм: {cls._MODULE_NAME}')
    print(f'Ключ: {key}')
    print(f'Сообщение:\n{msg}')

    vals = cls._MODULE_CAPABILITIES['enc'](
        key,
        msg,
        cls._MODULE_DEFAULT_ALPHABET_SET['a']
    )

    print(f'Зашифрованные данные:\n{vals}')
    if c_vals != 0:
        print(
            'Данные зашифрованы успешно? '\
            f'{["Нет", "Да"][vals == c_vals]}'
        )

    if len(sys.argv) > 1 and sys.argv[1] == 'pt':
        LBuffer.print_blocks_n_m(vals, 5, 4)

    global_data['enc'] = vals
    global_data['msg_size'] = len(msg)

    return True

def eval_test_dec(cls, control, global_data):
    msg, _, key = control

    print(f'Алгоритм: {cls._MODULE_NAME}')
    print(f'Ключ: {key}')

    if not 'enc' in global_data:
        print('Не могу расшифровать значение без предварительного шифрования')
        return

    vals = cls._MODULE_CAPABILITIES['dec'](
        key,
        global_data['enc'],
        cls._MODULE_DEFAULT_ALPHABET_SET['a']
    )
    print('Расшифрованные данные:')
    print(vals)

    vals = vals[:global_data['msg_size']]
    message = share.text_format(
        vals,
        cls._MODULE_DEFAULT_ALPHABET_SET['from']
    )

    print('Cообщение:')
    print(share.text_format(message, share.rules_rv_format))
    print(
        'Cообщение верно? '\
        f'{["Нет", "Да"][vals == msg]}'
    )

    return vals == msg

def eval_test_sig(cls, control, global_data):
    msg, c_vals, key = control

    vals = cls._MODULE_CAPABILITIES['sig'](
        key,
        msg,
        cls._MODULE_DEFAULT_ALPHABET_SET['a']
    )

    print(f'Алгоритм: {cls._MODULE_NAME}')
    print(f'Ключ: {key}')
    print('Сообщение:')
    print(msg)
    print('Подпись сообщения:')
    print(vals)
    if c_vals != 0:
        print(
            'Данные подписаны успешно? '\
            f'{["Нет", "Да"][vals == c_vals]}'
        )

    if len(sys.argv) > 1 and sys.argv[1] == 'pt':
        LBuffer.print_blocks_n_m(vals, 5, 4)

    global_data['sig'] = vals

    return True

def eval_test_ver(cls, control, global_data):
    msg, _, key = control

    print(f'Алгоритм: {cls._MODULE_NAME}')
    print(f'Ключ: {key}')

    if not 'sig' in global_data:
        print('Не могу проверить подпись без предварительного подписывания')
        return

    vals = cls._MODULE_CAPABILITIES['ver'](
        key,
        msg,
        global_data['sig'],
        cls._MODULE_DEFAULT_ALPHABET_SET['a']
    )
    print(
        'Подпись верна? '\
        f'{["Нет", "Да"][vals]}'
    )

    return vals


supported_tests = {
    'enc': eval_test_enc,
    'dec': eval_test_dec,
    'sig': eval_test_sig,
    'ver': eval_test_ver,
    'kec': eval_test_kec,
    'kee': eval_test_kee,
}

def eval_test(cls, test_cases, capabilities=None):
    if capabilities is None:
        capabilities = cls._MODULE_CAPABILITIES

    for control in test_cases:
        control[0] = share.text_format(
            control[0],
            cls._MODULE_DEFAULT_ALPHABET_SET['to']
        )

        global_data = {}
        for k in capabilities:
            if not k in  cls._MODULE_CAPABILITIES:
                continue
            if not k in supported_tests:
                print('Тестирование данного метода не реализовано')
                continue

            supported_tests[k](cls, control, global_data)
            print('')

def fill_data(fields):
    result = {}
    for k, desc, proc in fields:
        result[k] = proc(input(f'{k} ({desc}): '))

    return result

def eval_module(cls, message):
    print(
        f'{cls._MODULE_NAME} \n'
        + 's - Задать ключ\n'
        + 'm - Изменить сообщение\n'
        + 'q - Выйти'
    )
    for k in cls._MODULE_CAPABILITIES:
        print(f'{k} - {supported_capabilities[k]}')

    control = [message, 0, None]
    global_data = {}

    control[0] = share.text_format(
        control[0],
        cls._MODULE_DEFAULT_ALPHABET_SET['to']
    )

    while True:
        cmd_argv = str(input(': ')).split(' ')
        cmd_argc = len(cmd_argv)
        if cmd_argc == 0:
            continue

        cmd = cmd_argv[0]
        if cmd == 'q':
            break
        elif cmd == 's':
            try:
                control[2] = fill_data(cls._MODULE_KEY_PARAMS)
            except Exception as e:
                print(f'Не удалось обновить ключ. ({str(e)})')
        elif cmd == 'm':
            message = str(input('> '))
            control[0] = share.text_format(
                message,
                cls._MODULE_DEFAULT_ALPHABET_SET['to']
            )
        elif cmd == 'kyg' and 'kyg' in cls._MODULE_CAPABILITIES:
            while True:
                try:
                    key_params = fill_data(cls._MODULE_KEYGEN_PARAMS)
                    break
                except(ValueError):
                    print('Введено неверное значение, попробуйте ещё раз')


            control[2] = cls._MODULE_CAPABILITIES['kyg'](key_params)
            print(f'Параметры ключа: {control[2]}')

            if (cmd_argc != 3):
                continue

            methods = {}
            if cmd_argv[1] == 'b':
                if (
                    cmd_argv[2] == 'ed'
                    and 'enc' in cls._MODULE_CAPABILITIES
                    and 'dec'in cls._MODULE_CAPABILITIES
                ):
                    methods = {
                        'to': supported_tests['enc'],
                        'from': supported_tests['dec']
                    }
                elif (
                    cmd_argv[2] == 'sv'
                    and 'sig' in cls._MODULE_CAPABILITIES
                    and 'ver'in cls._MODULE_CAPABILITIES
                ):
                    methods = {
                        'to': supported_tests['sig'],
                        'from': supported_tests['ver']
                    }
                else:
                    print('Неизвестный режим проверки ключа')
                    continue
            else:
                continue

            while True:
                keygen_data = {}

                methods['to'](cls, control, keygen_data)

                if methods['from'](cls, control, keygen_data):
                    print('КЛЮЧ РАБОТАЕТ!')
                    print(f'Параметры ключа: {control[2]}')
                    break
                else:
                    print('Ключ не работает, генерируем новый')

                control[2] = cls._MODULE_CAPABILITIES['kyg'](key_params)
        elif control[2] is None:
            print('Необходимо задать(s) или сгенерировать ключ(kyg)')
        elif cmd in cls._MODULE_CAPABILITIES and cmd in supported_tests:
            supported_tests[cmd](
                cls, control, global_data
            )
        else:
            print(f'команда "{cmd}" не поддерживается')

def eval_interface(modules_list):
    message = str(input('Введите сообщение: '))
    modules_cnt = len(modules_list)

    while True:
        print('Выбирите модуль: ')

        cnt = 0
        print('q - Выход')
        for m in modules_list:
            print(f'{cnt} - {m._MODULE_NAME}')
            cnt += 1

        cmd = input(': ')
        if cmd == 'q':
            break

        cmd = int(cmd)
        if cmd >= modules_cnt:
            continue

        eval_module(modules_list[cmd], message)
