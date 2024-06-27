from b00_interface import eval_test
from t19_aes import aes

aes_testcases = [
    [
        'Выпущенное слово и камень не имеют возврата.',
        32318653674238356680410450332100272175998783784651186592254222318135604513617,
        {
            'm': 1, # AES-192
            'key': 0xb12841663
        }
    ],
    [
        'Настоящий стандарт определяет алгоритмы базовых блочных шифров, которые применяются в криптографических методах обработки и защиты информации, в том числе для обеспечения конфиденциальности, аутентичности и целостности информации при её передаче, обработке и хранении в автоматизированных системах. Определённые в настоящем стандарте алгоритмы криптографического преобразования предназначены для аппаратной или программной реализации, удовлетворяют современным криптографическим требованиям и по своим возможностям не накладывают ограничений на степень секретности защищаемой информации. Стандарт рекомендуется использовать при создании, эксплуатации и модернизации систем обработки информации различного назначения. Термины, определения и обозначения. П р и м е ч а н и е, В настоящем стандарте в целях сохранения терминологической преемственности по отношению к опубликованным научно-техническим изданиям применяется термин шифрование, объединяющий операции, определённые терминами зашифрование и расшифрование. Конкретное значение термина шифрование определяется в зависимости от контекста упоминания.',
        4295246028937034058845043389194554285256000575083291768796804866906893188581512103638827416516196867105001043954246947085038514206105481091904869614526895924461202414332118061319836311539775239233860808837396676260048084004063092495887639214058337473340844723032428891846917317496923738779299409290470201665459488383121179118446034294150194323234065487466814621915817279783406739833136331903598633287621359754130223086705564195217804591056289006575976513083038934715992308475532139980458503282714096371175495017504549880383400995384767386307271578298817452372125831545073769762601093900388213688534818254844541484133018730098127566429204839400837704486702792093465881635926257858163198829569848631809841125324444714611643707032711546748651885953677105249902029929509484507403011303438154474868857429147748594451864492446356299598129696022957886124974615529511859916985036115117236295266260303105972327669512590521291055009719840065538467473003415297352607737822589442234236558337435124622892117935470305428003820137183127825274102344961231556842407052160145290228829385951447895636517922378045383936707079751931759125096387077031800124249369965501371486811684087953908530642686396562928349833676439949078143953166052260736395583530104608795991690439586645893494799241759546425707776696176293270557060709538466664168988454633462124854910098199891124503658827282033709536618079783116230196911724030559970793163577490168349048537909078027506642998906765026510074531573782485133069883185710851649213541680129076263656149058815782420330635639189439970592559914497980669117652119340769678922966140953709882288597048111404819898703602303527188113547778874996524108766032987216286456920210968685700601550461454440449978394341400775761890030572499477549039366288675342549904956504893433635257187076764152973953586456115492919805707868648125243799128247013950,
        {
            'm': 2, # AES-256
            'key': 0xe64a16c66a50de970e5eb551637ca51ec1c2342254023f31ae0d7d3dd6b5cbe9
        }
    ]
]

class aes_test:
    @staticmethod
    def _sub_bytes():
        valid = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
        ]

        for i in range(len(valid)):
            res = aes._sub_bytes(i, 1)
            if res != valid[i]:
                raise Exception(f'_sub_bytes test failed. {hex(res)} != {hex(valid[i])}')

    @staticmethod
    def _inv_sub_bytes():
        valid = [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
        ]

        for i in range(len(valid)):
            res = aes._inv_sub_bytes(i, 1)
            if res != valid[i]:
                raise Exception(f'_sub_bytes test failed. {hex(res)} != {hex(valid[i])}')

    @staticmethod
    def _key_shedule_128():
        res = 0x2b7e151628aed2a6abf7158809cf4f3c
        valid = [
            0x2b7e1516,
            0x28aed2a6,
            0xabf71588,
            0x09cf4f3c,

            0xa0fafe17,
            0x88542cb1,
            0x23a33939,
            0x2a6c7605,
            0xf2c295f2,
            0x7a96b943,
            0x5935807a,
            0x7359f67f,
            0x3d80477d,
            0x4716fe3e,
            0x1e237e44,
            0x6d7a883b,
            0xef44a541,
            0xa8525b7f,
            0xb671253b,
            0xdb0bad00,
            0xd4d1c6f8,
            0x7c839d87,
            0xcaf2b8bc,
            0x11f915bc,
            0x6d88a37a,
            0x110b3efd,
            0xdbf98641,
            0xca0093fd,
            0x4e54f70e,
            0x5f5fc9f3,
            0x84a64fb2,
            0x4ea6dc4f,
            0xead27321,
            0xb58dbad2,
            0x312bf560,
            0x7f8d292f,
            0xac7766f3,
            0x19fadc21,
            0x28d12941,
            0x575c006e,
            0xd014f9a8,
            0xc9ee2589,
            0xe13f0cc8,
            0xb6630ca6,
        ]

        res = aes._key_shedule(res, aes.B128)
        for i in range(len(valid)):
            if res[i] != valid[i]:
                raise Exception(f'_key_shedule test failed. {hex(res[i])} != {hex(valid[i])}')

    @staticmethod
    def _key_shedule_192():
        res = 0x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
        valid = [
            0x8e73b0f7,
            0xda0e6452,
            0xc810f32b,
            0x809079e5,
            0x62f8ead2,
            0x522c6b7b,

            0xfe0c91f7,
            0x2402f5a5,
            0xec12068e,
            0x6c827f6b,
            0x0e7a95b9,
            0x5c56fec2,
            0x4db7b4bd,
            0x69b54118,
            0x85a74796,
            0xe92538fd,
            0xe75fad44,
            0xbb095386,
            0x485af057,
            0x21efb14f,
            0xa448f6d9,
            0x4d6dce24,
            0xaa326360,
            0x113b30e6,
            0xa25e7ed5,
            0x83b1cf9a,
            0x27f93943,
            0x6a94f767,
            0xc0a69407,
            0xd19da4e1,
            0xec1786eb,
            0x6fa64971,
            0x485f7032,
            0x22cb8755,
            0xe26d1352,
            0x33f0b7b3,
            0x40beeb28,
            0x2f18a259,
            0x6747d26b,
            0x458c553e,
            0xa7e1466c,
            0x9411f1df,
            0x821f750a,
            0xad07d753,
            0xca400538,
            0x8fcc5006,
            0x282d166a,
            0xbc3ce7b5,
            0xe98ba06f,
            0x448c773c,
            0x8ecc7204,
            0x01002202,
        ]

        res = aes._key_shedule(res, aes.B192)
        for i in range(len(valid)):
            if res[i] != valid[i]:
                raise Exception(f'_key_shedule test failed. {hex(res[i])} != {hex(valid[i])}')

    @staticmethod
    def _key_shedule_256():
        res = 0x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
        valid = [
            0x603deb10,
            0x15ca71be,
            0x2b73aef0,
            0x857d7781,
            0x1f352c07,
            0x3b6108d7,
            0x2d9810a3,
            0x0914dff4,

            0x9ba35411,
            0x8e6925af,
            0xa51a8b5f,
            0x2067fcde,
            0xa8b09c1a,
            0x93d194cd,
            0xbe49846e,
            0xb75d5b9a,
            0xd59aecb8,
            0x5bf3c917,
            0xfee94248,
            0xde8ebe96,
            0xb5a9328a,
            0x2678a647,
            0x98312229,
            0x2f6c79b3,
            0x812c81ad,
            0xdadf48ba,
            0x24360af2,
            0xfab8b464,
            0x98c5bfc9,
            0xbebd198e,
            0x268c3ba7,
            0x09e04214,
            0x68007bac,
            0xb2df3316,
            0x96e939e4,
            0x6c518d80,
            0xc814e204,
            0x76a9fb8a,
            0x5025c02d,
            0x59c58239,
            0xde136967,
            0x6ccc5a71,
            0xfa256395,
            0x9674ee15,
            0x5886ca5d,
            0x2e2f31d7,
            0x7e0af1fa,
            0x27cf73c3,
            0x749c47ab,
            0x18501dda,
            0xe2757e4f,
            0x7401905a,
            0xcafaaae3,
            0xe4d59b34,
            0x9adf6ace,
            0xbd10190d,
            0xfe4890d1,
            0xe6188d0b,
            0x046df344,
            0x706c631e,
        ]

        res = aes._key_shedule(res, aes.B256)
        for i in range(len(valid)):
            if res[i] != valid[i]:
                raise Exception(f'_key_shedule test failed. {hex(res[i])} != {hex(valid[i])}')

    @staticmethod
    def _encrypt_block_128():
        key = 0x000102030405060708090a0b0c0d0e0f
        data = 0x00112233445566778899aabbccddeeff
        valid = 0x69c4e0d86a7b0430d8cdb78070b4c55a

        res = aes._encrypt_block(key, data, aes.B128)
        if res != valid:
            raise Exception(f'_encrypt_block test failed. {hex(res)} != {hex(valid)}')

    @staticmethod
    def _decrypt_block_128():
        key = 0x000102030405060708090a0b0c0d0e0f
        ciphertext = 0x69c4e0d86a7b0430d8cdb78070b4c55a
        valid = 0x00112233445566778899aabbccddeeff

        res = aes._decrypt_block(key, ciphertext, aes.B128)
        if res != valid:
            raise Exception(f'_decrypt_block test failed. {hex(res)} != {hex(valid)}')

    @staticmethod
    def _encrypt_block_192():
        key = 0x000102030405060708090a0b0c0d0e0f1011121314151617
        data = 0x00112233445566778899aabbccddeeff
        valid = 0xdda97ca4864cdfe06eaf70a0ec0d7191

        res = aes._encrypt_block(key, data, aes.B192)
        if res != valid:
            raise Exception(f'_encrypt_block test failed. {hex(res)} != {hex(valid)}')

    @staticmethod
    def _decrypt_block_192():
        key = 0x000102030405060708090a0b0c0d0e0f1011121314151617
        ciphertext = 0xdda97ca4864cdfe06eaf70a0ec0d7191
        valid = 0x00112233445566778899aabbccddeeff

        res = aes._decrypt_block(key, ciphertext, aes.B192)
        if res != valid:
            raise Exception(f'_decrypt_block test failed. {hex(res)} != {hex(valid)}')

    @staticmethod
    def _encrypt_block_256():
        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        data = 0x00112233445566778899aabbccddeeff
        valid = 0x8ea2b7ca516745bfeafc49904b496089

        res = aes._encrypt_block(key, data, aes.B256)
        if res != valid:
            raise Exception(f'_encrypt_block test failed. {hex(res)} != {hex(valid)}')

    @staticmethod
    def _decrypt_block_256():
        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        ciphertext = 0x8ea2b7ca516745bfeafc49904b496089
        valid = 0x00112233445566778899aabbccddeeff

        res = aes._decrypt_block(key, ciphertext, aes.B256)
        if res != valid:
            raise Exception(f'_decrypt_block test failed. {hex(res)} != {hex(valid)}')


if __name__ == "__main__":
    aes_test._sub_bytes()
    aes_test._inv_sub_bytes()
    aes_test._key_shedule_128()
    aes_test._key_shedule_192()
    aes_test._key_shedule_256()
    aes_test._encrypt_block_128()
    aes_test._encrypt_block_192()
    aes_test._encrypt_block_256()
    aes_test._decrypt_block_128()
    aes_test._decrypt_block_192()
    aes_test._decrypt_block_256()

    eval_test(aes.ECB_wrap, aes_testcases)
