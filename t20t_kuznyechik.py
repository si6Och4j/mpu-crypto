from b00_interface import eval_test
from t07_gost_r_34_12 import kuznyechik

kuznyechik_testcases = [
    [
        'Выпущенное слово и камень не имеют возврата.',
        49607092221472638651315511312365037346858929855836619509675973148837415680750,
        {
            'key': 0xb12841663
        }
    ],
    [
        'Настоящий стандарт определяет алгоритмы базовых блочных шифров, которые применяются в криптографических методах обработки и защиты информации, в том числе для обеспечения конфиденциальности, аутентичности и целостности информации при её передаче, обработке и хранении в автоматизированных системах. Определённые в настоящем стандарте алгоритмы криптографического преобразования предназначены для аппаратной или программной реализации, удовлетворяют современным криптографическим требованиям и по своим возможностям не накладывают ограничений на степень секретности защищаемой информации. Стандарт рекомендуется использовать при создании, эксплуатации и модернизации систем обработки информации различного назначения. Термины, определения и обозначения. П р и м е ч а н и е, В настоящем стандарте в целях сохранения терминологической преемственности по отношению к опубликованным научно-техническим изданиям применяется термин шифрование, объединяющий операции, определённые терминами зашифрование и расшифрование. Конкретное значение термина шифрование определяется в зависимости от контекста упоминания.',
        0x3515899d61e6b62d4b88024a95be63b7a86b0a2a2bc354e7eaf42ea21794e0abde584d2c457409704cf825c1967124158fb33ff1fdb8245d9bbe83cf9983dbd297d711e88d97db124f793c95a7760871cd95ac9d26c1148714b8c775ded2f98ddf4ac871075cb42e894671d72b77981398a811bf8a7c87934a675f3a33285ba1fa4dd25051e153399b14960465b189267b8402924b4c4cbfbf005e9b8e0e2a7bbd866a1aa9b62c4b78f8f4b57d2b234934ea164279c2b067b0cd9ab32d89ef8a014f66accf2b184998fa3110d0c09c3fbaa4dfde18b35c97ab39e52cd80f3e2f516a9e77eb6d7c4d896d2212de735b35ffb813f299ffc56abfbe9608b57347912ac06e188aa7bf6371faec719d1132cb843a8e80251b672f2da37b92bb7535ef0de91d3cc06daee79909ca4bfe440295e31344c75b99a524c673326e8525782036c676400585d4cd83e71964dc7be44efb5b3ec53c11f3411ece6462d85baa9d4cf473d68902a6cc6e2f2cd962c986c72e51772da67d67b12ab9b0650f4d845fb88bcbdf35127e05dc77575682c20c1d5a734a952a269108dfda0b6410ca54a296c96a06b9eaf01bc6326b056d06cdbf14a14700e8a48e97ef4c2a0f77750111c858a5e130cab6b0340475af66620cd7fd8ddb1da3596fe9c39947399a15dc0d4d054184b55d0d4c9de5ff6668fa981d4cbf301e29a9a4952016ada8fc8103ba7d6e50d325372b8ca3640f10e82c3f3f3dcafcca62e54f7472e4858d0535c79682f1150dcd4654227ce5d2259b0e1c2a5af0548c47b0078629d9515458ebd8f6a40b12385439b7d0c74229606d52f12d1f93ab92c0a3be396510160408b1fbf02e089243be118ecd7eccbd2a33f9d4b5c3f9484ed76ae915ef690cbbfaa28084b10fa3ef8ffd84dc8988539d0282f77eb2807bd96119b372f36c0201f988165c514f9a387ab21dfa38268c5dcf1d2bdb2f4875fb8cbb455d358387f9b180c981a6ee5d021acaefe1886eac7d664d01f8d1becf31dbb69d7278cc3ec15d1adbfdb0b08d30330c940e539e4b8538758249b16fd342989b702eded7c6e691664322,
        {
            'key': 0x6d1ac192af48d6010f092961e8c3286f1c0521d60de84c33109218479d778586
        }
    ]
]

class kuznyechik_test:
    @staticmethod
    def _s_transform():
        res = 0xffeeddccbbaa99881122334455667700
        valid = [
            0xb66cd8887d38e8d77765aeea0c9a7efc,
            0x559d8dd7bd06cbfe7e7b262523280d39,
            0x0c3322fed531e4630d80ef5c5a81c50b,
            0x23ae65633f842d29c5df529c13f5acda,
        ]

        for valid_i in valid:
            res = kuznyechik._s_transform(res)
            if res != valid_i:
                raise Exception(f'_s_transform test failed. {hex(res)} != {hex(valid_i)}')

    @staticmethod
    def _s_transform_r():
        res = 0x23ae65633f842d29c5df529c13f5acda
        valid = [
            0x0c3322fed531e4630d80ef5c5a81c50b,
            0x559d8dd7bd06cbfe7e7b262523280d39,
            0xb66cd8887d38e8d77765aeea0c9a7efc,
            0xffeeddccbbaa99881122334455667700,
        ]

        for valid_i in valid:
            res = kuznyechik._s_transform_r(res)
            if res != valid_i:
                raise Exception(f'_s_transform_r test failed. {hex(res)} != {hex(valid_i)}')

    @staticmethod
    def _r_transform():
        res = 0x00000000000000000000000000000100
        valid = [
            0x94000000000000000000000000000001,
            0xa5940000000000000000000000000000,
            0x64a59400000000000000000000000000,
            0x0d64a594000000000000000000000000,
        ]

        for valid_i in valid:
            res = kuznyechik._r_transform(res)
            if res != valid_i:
                raise Exception(f'_r_transform test failed. {hex(res)} != {hex(valid_i)}')

    @staticmethod
    def _r_transform_r():
        res = 0x0d64a594000000000000000000000000
        valid = [
            0x64a59400000000000000000000000000,
            0xa5940000000000000000000000000000,
            0x94000000000000000000000000000001,
            0x100,
        ]

        for valid_i in valid:
            res = kuznyechik._r_transform_r(res)
            if res != valid_i:
                raise Exception(f'_r_transform_r test failed. {hex(res)} != {hex(valid_i)}')

    @staticmethod
    def _l_transform():
        res = 0x64a59400000000000000000000000000
        valid = [
            0xd456584dd0e3e84cc3166e4b7fa2890d,
            0x79d26221b87b584cd42fbc4ffea5de9a,
            0x0e93691a0cfc60408b7b68f66b513c13,
            0xe6a8094fee0aa204fd97bcb0b44b8580,
        ]

        for valid_i in valid:
            res = kuznyechik._l_transform(res)
            if res != valid_i:
                raise Exception(f'_l_transform test failed. {hex(res)} != {hex(valid_i)}')

    @staticmethod
    def _l_transform_r():
        res = 0xe6a8094fee0aa204fd97bcb0b44b8580
        valid = [
            0x0e93691a0cfc60408b7b68f66b513c13,
            0x79d26221b87b584cd42fbc4ffea5de9a,
            0xd456584dd0e3e84cc3166e4b7fa2890d,
            0x64a59400000000000000000000000000,
        ]

        for valid_i in valid:
            res = kuznyechik._l_transform_r(res)
            if res != valid_i:
                raise Exception(f'_l_transform_r test failed. {hex(res)} != {hex(valid_i)}')

    @staticmethod
    def _key_shedule():
        res = 0x8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
        valid = [
            0x8899aabbccddeeff0011223344556677,
            0xfedcba98765432100123456789abcdef,
            0xdb31485315694343228d6aef8cc78c44,
            0x3d4553d8e9cfec6815ebadc40a9ffd04,
            0x57646468c44a5e28d3e59246f429f1ac,
            0xbd079435165c6432b532e82834da581b,
            0x51e640757e8745de705727265a0098b1,
            0x5a7925017b9fdd3ed72a91a22286f984,
            0xbb44e25378c73123a5f32f73cdb6e517,
            0x72e9dd7416bcf45b755dbaa88e4a4043,
        ]

        res = kuznyechik._key_shedule(res)
        for i in range(len(valid)):
            if res[i] != valid[i]:
                raise Exception(f'_key_shedule test failed. {hex(res[i])} != {hex(valid[i])}')

    @staticmethod
    def _encrypt_block():
        key = 0x8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
        data = 0x1122334455667700ffeeddccbbaa9988
        valid = 0x7f679d90bebc24305a468d42b9d4edcd

        res = kuznyechik._encrypt_block(key, data)
        if res != valid:
            raise Exception(f'_encrypt_block test failed. {hex(res)} != {hex(valid)}')

    @staticmethod
    def _decrypt_block():
        key = 0x8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
        ciphertext = 0x7f679d90bebc24305a468d42b9d4edcd
        valid = 0x1122334455667700ffeeddccbbaa9988

        res = kuznyechik._decrypt_block(key, ciphertext)
        if res != valid:
            raise Exception(f'_decrypt_block test failed. {hex(res)} != {hex(valid)}')

    class ECB:
        @staticmethod
        def encrypt():
            key = 0x8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
            data = 0x8912409b17b57e414a98fb2e67a8024cdb54c704f8189d2092def06b3c130a59
            valid = 0xd2600fed82f0bb3c4e1e5cee0ae72b0d6d00a52bceb02807d6e65646c2e2a2a4

            res = kuznyechik.ECB.encrypt(key, data)
            if res != valid:
                raise Exception(f'ECB.encrypt test failed. {hex(res)} != {hex(valid)}')

        @staticmethod
        def decrypt():
            key = 0x8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
            ciphertext = 0xd2600fed82f0bb3c4e1e5cee0ae72b0d6d00a52bceb02807d6e65646c2e2a2a4
            valid = 0x8912409b17b57e414a98fb2e67a8024cdb54c704f8189d2092def06b3c130a59

            res = kuznyechik.ECB.decrypt(key, ciphertext)
            if res != valid:
                raise Exception(f'ECB.decrypt test failed. {hex(res)} != {hex(valid)}')


if __name__ == "__main__":
    kuznyechik_test._s_transform()
    kuznyechik_test._s_transform_r()
    kuznyechik_test._r_transform()
    kuznyechik_test._r_transform_r()
    kuznyechik_test._l_transform()
    kuznyechik_test._l_transform_r()
    kuznyechik_test._key_shedule()
    kuznyechik_test._encrypt_block()
    kuznyechik_test._decrypt_block()

    kuznyechik_test.ECB.encrypt()
    kuznyechik_test.ECB.decrypt()

    eval_test(kuznyechik.ECB_wrap, kuznyechik_testcases)
