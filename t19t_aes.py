from b00_interface import eval_test
from t19_aes import rijndeal
import share

rijndeal_testcases = [
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
    ],
    [
        'Настоящий стандарт определяет алгоритмы базовых блочных шифров, которые применяются в криптографических методах обработки и защиты информации, в том числе для обеспечения конфиденциальности, аутентичности и целостности информации при её передаче, обработке и хранении в автоматизированных системах. Определённые в настоящем стандарте алгоритмы криптографического преобразования предназначены для аппаратной или программной реализации, удовлетворяют современным криптографическим требованиям и по своим возможностям не накладывают ограничений на степень секретности защищаемой информации. Стандарт рекомендуется использовать при создании, эксплуатации и модернизации систем обработки информации различного назначения. Термины, определения и обозначения. П р и м е ч а н и е, В настоящем стандарте в целях сохранения терминологической преемственности по отношению к опубликованным научно-техническим изданиям применяется термин шифрование, объединяющий операции, определённые терминами зашифрование и расшифрование. Конкретное значение термина шифрование определяется в зависимости от контекста упоминания.',
        30358754829553227362994074935168052085461351857232824786374508893881739867469539685252121288895964891187056481427509425029098773180238810272977305175203141609626029143910629897575699624206670741286803024722893175293022788470821298236250760791146743426448433501439572479334453978648429892254475827002367110699979964855224546513850836557679170015147044622009959546056135859822240740346215250499971169155693604700185400096744039630577915637152211031960264531837970008005278819362403037974188545787386117455242582059331769777916007810242891288607269639966705137458341924190221262705756650825814929694272327055329742636511620590661906723780070619302829139433328323409598000363040129849053657577251892050098621000205759633474860319143595196723550850439480993804132293598159203862191327733643937455250705045361088874941748634335727994708013336886413273981075936243229986975471024681639728887192677849350338346459954288610085068408801512815897338354564223594120327747136284525314071017399945421106545670599261370154732784378692026295522065532414018005526661371746638598962993895224459930675886968517934655775523551501190775727965588964006727559524864333990037194284541049723916181169941765198481524254892296065514738235231574503043826223038070475819199336908659791945371481858980044508708702920011159692206200130684335059814215186519094554613324973073284321689022473315545620250433480045112546303355807871416491793565186218574287300635893469646345461059386978632450869083037275503434716855809600199367075736224122444960904335635611689912702711977481446358086718041414536921099278340815508349431908938588965658424061087757071615753228141106689708695290577449906174073895741704509809034359676442894437485078201261833449236788889689542953520184135101258658428804176533484425641606272134433626045417220290168284313256597429879227963794857852780595041969496515752,
        {
            'm': 3, # Rijndeal-256
            'key': 0xe64a16c66a50de970e5eb551637ca51ec1c2342254023f31ae0d7d3dd6b5cbe9
        }
    ]
]

class rijndeal_test:
    @staticmethod
    def _sub_bytes():
        valid = [
            0x63636363, 0x6363637c, 0x63636377, 0x6363637b, 0x636363f2, 0x6363636b, 0x6363636f, 0x636363c5, 0x63636330, 0x63636301, 0x63636367, 0x6363632b, 0x636363fe, 0x636363d7, 0x636363ab,0x63636376,
            0x636363ca, 0x63636382, 0x636363c9, 0x6363637d, 0x636363fa, 0x63636359, 0x63636347, 0x636363f0, 0x636363ad, 0x636363d4, 0x636363a2, 0x636363af, 0x6363639c, 0x636363a4, 0x63636372,0x636363c0,
            0x636363b7, 0x636363fd, 0x63636393, 0x63636326, 0x63636336, 0x6363633f, 0x636363f7, 0x636363cc, 0x63636334, 0x636363a5, 0x636363e5, 0x636363f1, 0x63636371, 0x636363d8, 0x63636331,0x63636315,
            0x63636304, 0x636363c7, 0x63636323, 0x636363c3, 0x63636318, 0x63636396, 0x63636305, 0x6363639a, 0x63636307, 0x63636312, 0x63636380, 0x636363e2, 0x636363eb, 0x63636327, 0x636363b2,0x63636375,
            0x63636309, 0x63636383, 0x6363632c, 0x6363631a, 0x6363631b, 0x6363636e, 0x6363635a, 0x636363a0, 0x63636352, 0x6363633b, 0x636363d6, 0x636363b3, 0x63636329, 0x636363e3, 0x6363632f,0x63636384,
            0x63636353, 0x636363d1, 0x63636300, 0x636363ed, 0x63636320, 0x636363fc, 0x636363b1, 0x6363635b, 0x6363636a, 0x636363cb, 0x636363be, 0x63636339, 0x6363634a, 0x6363634c, 0x63636358,0x636363cf,
            0x636363d0, 0x636363ef, 0x636363aa, 0x636363fb, 0x63636343, 0x6363634d, 0x63636333, 0x63636385, 0x63636345, 0x636363f9, 0x63636302, 0x6363637f, 0x63636350, 0x6363633c, 0x6363639f,0x636363a8,
            0x63636351, 0x636363a3, 0x63636340, 0x6363638f, 0x63636392, 0x6363639d, 0x63636338, 0x636363f5, 0x636363bc, 0x636363b6, 0x636363da, 0x63636321, 0x63636310, 0x636363ff, 0x636363f3,0x636363d2,
            0x636363cd, 0x6363630c, 0x63636313, 0x636363ec, 0x6363635f, 0x63636397, 0x63636344, 0x63636317, 0x636363c4, 0x636363a7, 0x6363637e, 0x6363633d, 0x63636364, 0x6363635d, 0x63636319,0x63636373,
            0x63636360, 0x63636381, 0x6363634f, 0x636363dc, 0x63636322, 0x6363632a, 0x63636390, 0x63636388, 0x63636346, 0x636363ee, 0x636363b8, 0x63636314, 0x636363de, 0x6363635e, 0x6363630b,0x636363db,
            0x636363e0, 0x63636332, 0x6363633a, 0x6363630a, 0x63636349, 0x63636306, 0x63636324, 0x6363635c, 0x636363c2, 0x636363d3, 0x636363ac, 0x63636362, 0x63636391, 0x63636395, 0x636363e4,0x63636379,
            0x636363e7, 0x636363c8, 0x63636337, 0x6363636d, 0x6363638d, 0x636363d5, 0x6363634e, 0x636363a9, 0x6363636c, 0x63636356, 0x636363f4, 0x636363ea, 0x63636365, 0x6363637a, 0x636363ae,0x63636308,
            0x636363ba, 0x63636378, 0x63636325, 0x6363632e, 0x6363631c, 0x636363a6, 0x636363b4, 0x636363c6, 0x636363e8, 0x636363dd, 0x63636374, 0x6363631f, 0x6363634b, 0x636363bd, 0x6363638b,0x6363638a,
            0x63636370, 0x6363633e, 0x636363b5, 0x63636366, 0x63636348, 0x63636303, 0x636363f6, 0x6363630e, 0x63636361, 0x63636335, 0x63636357, 0x636363b9, 0x63636386, 0x636363c1, 0x6363631d,0x6363639e,
            0x636363e1, 0x636363f8, 0x63636398, 0x63636311, 0x63636369, 0x636363d9, 0x6363638e, 0x63636394, 0x6363639b, 0x6363631e, 0x63636387, 0x636363e9, 0x636363ce, 0x63636355, 0x63636328,0x636363df,
            0x6363638c, 0x636363a1, 0x63636389, 0x6363630d, 0x636363bf, 0x636363e6, 0x63636342, 0x63636368, 0x63636341, 0x63636399, 0x6363632d, 0x6363630f, 0x636363b0, 0x63636354, 0x636363bb,0x63636316,
        ]

        for i in range(len(valid)):
            res = rijndeal._sub_bytes([i], 1)[0]
            if res != valid[i]:
                raise Exception(f'_sub_bytes test failed. {hex(res)} != {hex(valid[i])}')

    @staticmethod
    def _prod_sub_bytes():
        data = [
            0xe9f84808,
            0x9ac68d2a,
            0xa0f4e22b,
            0x193de3be,
        ]
        valid = [
            0x1e415230,
            0xb8b45de5,
            0xe0bf98f1,
            0xd42711ae,
        ]
        rijndeal._sub_bytes(data, 4)

        for i in range(len(valid)):
            if data[i] != valid[i]:
                raise Exception(f'_sub_bytes test failed. {hex(data[i])} != {hex(valid[i])}')

    @staticmethod
    def _inv_sub_bytes():
        valid = [
            0x52525252, 0x52525209, 0x5252526a, 0x525252d5, 0x52525230, 0x52525236, 0x525252a5, 0x52525238, 0x525252bf, 0x52525240, 0x525252a3, 0x5252529e, 0x52525281, 0x525252f3, 0x525252d7, 0x525252fb,
            0x5252527c, 0x525252e3, 0x52525239, 0x52525282, 0x5252529b, 0x5252522f, 0x525252ff, 0x52525287, 0x52525234, 0x5252528e, 0x52525243, 0x52525244, 0x525252c4, 0x525252de, 0x525252e9, 0x525252cb,
            0x52525254, 0x5252527b, 0x52525294, 0x52525232, 0x525252a6, 0x525252c2, 0x52525223, 0x5252523d, 0x525252ee, 0x5252524c, 0x52525295, 0x5252520b, 0x52525242, 0x525252fa, 0x525252c3, 0x5252524e,
            0x52525208, 0x5252522e, 0x525252a1, 0x52525266, 0x52525228, 0x525252d9, 0x52525224, 0x525252b2, 0x52525276, 0x5252525b, 0x525252a2, 0x52525249, 0x5252526d, 0x5252528b, 0x525252d1, 0x52525225,
            0x52525272, 0x525252f8, 0x525252f6, 0x52525264, 0x52525286, 0x52525268, 0x52525298, 0x52525216, 0x525252d4, 0x525252a4, 0x5252525c, 0x525252cc, 0x5252525d, 0x52525265, 0x525252b6, 0x52525292,
            0x5252526c, 0x52525270, 0x52525248, 0x52525250, 0x525252fd, 0x525252ed, 0x525252b9, 0x525252da, 0x5252525e, 0x52525215, 0x52525246, 0x52525257, 0x525252a7, 0x5252528d, 0x5252529d, 0x52525284,
            0x52525290, 0x525252d8, 0x525252ab, 0x52525200, 0x5252528c, 0x525252bc, 0x525252d3, 0x5252520a, 0x525252f7, 0x525252e4, 0x52525258, 0x52525205, 0x525252b8, 0x525252b3, 0x52525245, 0x52525206,
            0x525252d0, 0x5252522c, 0x5252521e, 0x5252528f, 0x525252ca, 0x5252523f, 0x5252520f, 0x52525202, 0x525252c1, 0x525252af, 0x525252bd, 0x52525203, 0x52525201, 0x52525213, 0x5252528a, 0x5252526b,
            0x5252523a, 0x52525291, 0x52525211, 0x52525241, 0x5252524f, 0x52525267, 0x525252dc, 0x525252ea, 0x52525297, 0x525252f2, 0x525252cf, 0x525252ce, 0x525252f0, 0x525252b4, 0x525252e6, 0x52525273,
            0x52525296, 0x525252ac, 0x52525274, 0x52525222, 0x525252e7, 0x525252ad, 0x52525235, 0x52525285, 0x525252e2, 0x525252f9, 0x52525237, 0x525252e8, 0x5252521c, 0x52525275, 0x525252df, 0x5252526e,
            0x52525247, 0x525252f1, 0x5252521a, 0x52525271, 0x5252521d, 0x52525229, 0x525252c5, 0x52525289, 0x5252526f, 0x525252b7, 0x52525262, 0x5252520e, 0x525252aa, 0x52525218, 0x525252be, 0x5252521b,
            0x525252fc, 0x52525256, 0x5252523e, 0x5252524b, 0x525252c6, 0x525252d2, 0x52525279, 0x52525220, 0x5252529a, 0x525252db, 0x525252c0, 0x525252fe, 0x52525278, 0x525252cd, 0x5252525a, 0x525252f4,
            0x5252521f, 0x525252dd, 0x525252a8, 0x52525233, 0x52525288, 0x52525207, 0x525252c7, 0x52525231, 0x525252b1, 0x52525212, 0x52525210, 0x52525259, 0x52525227, 0x52525280, 0x525252ec, 0x5252525f,
            0x52525260, 0x52525251, 0x5252527f, 0x525252a9, 0x52525219, 0x525252b5, 0x5252524a, 0x5252520d, 0x5252522d, 0x525252e5, 0x5252527a, 0x5252529f, 0x52525293, 0x525252c9, 0x5252529c, 0x525252ef,
            0x525252a0, 0x525252e0, 0x5252523b, 0x5252524d, 0x525252ae, 0x5252522a, 0x525252f5, 0x525252b0, 0x525252c8, 0x525252eb, 0x525252bb, 0x5252523c, 0x52525283, 0x52525253, 0x52525299, 0x52525261,
            0x52525217, 0x5252522b, 0x52525204, 0x5252527e, 0x525252ba, 0x52525277, 0x525252d6, 0x52525226, 0x525252e1, 0x52525269, 0x52525214, 0x52525263, 0x52525255, 0x52525221, 0x5252520c, 0x5252527d,
        ]

        for i in range(len(valid)):
            res = [i]
            rijndeal._inv_sub_bytes(res, 1)
            if res[0] != valid[i]:
                raise Exception(f'_inv_sub_bytes test failed. {hex(res[0])} != {hex(valid[i])}')

    @staticmethod
    def _prod_inv_sub_bytes():
        data = [
            0x1e415230,
            0xb8b45de5,
            0xe0bf98f1,
            0xd42711ae,
        ]
        valid = [
            0xe9f84808,
            0x9ac68d2a,
            0xa0f4e22b,
            0x193de3be,
        ]

        rijndeal._inv_sub_bytes(data, 4)

        for i in range(len(valid)):
            if data[i] != valid[i]:
                raise Exception(f'_inv_sub_bytes test failed. {hex(data[i])} != {hex(valid[i])}')

    @staticmethod
    def _prod_shift_rows():
        data = [
            0x1e415230,
            0xb8b45de5,
            0xe0bf98f1,
            0xd42711ae,
        ]
        valid = [
            0x1e2798e5,
            0xb84111f1,
            0xe0b452ae,
            0xd4bf5d30,
        ]

        rijndeal._shift_rows(data, rijndeal.AES256)

        for i in range(len(valid)):
            if data[i] != valid[i]:
                raise Exception(f'_shift_rows test failed. {hex(data[i])} != {hex(valid[i])}')

    @staticmethod
    def _prod_inv_shift_rows():
        data = [
            0x1e2798e5,
            0xb84111f1,
            0xe0b452ae,
            0xd4bf5d30,
        ]
        valid = [
            0x1e415230,
            0xb8b45de5,
            0xe0bf98f1,
            0xd42711ae,
        ]

        rijndeal._inv_shift_rows(data, rijndeal.AES256)

        for i in range(len(valid)):
            if data[i] != valid[i]:
                raise Exception(f'_inv_shift_rows test failed. {hex(data[i])} != {hex(valid[i])}')

    @staticmethod
    def _prod_mix_columns():
        data = [
            0x1e2798e5,
            0xb84111f1,
            0xe0b452ae,
            0xd4bf5d30,
        ]
        valid = [
            0x2806264c,
            0x48f8d37a,
            0xe0cb199a,
            0x046681e5,
        ]

        rijndeal._mix_columns(data, rijndeal.AES256)

        for i in range(len(valid)):
            if data[i] != valid[i]:
                raise Exception(f'_mix_columns test failed. {hex(data[i])} != {hex(valid[i])}')

    @staticmethod
    def _prod_inv_mix_columns():
        data = [
            0x2806264c,
            0x48f8d37a,
            0xe0cb199a,
            0x046681e5,
        ]
        valid = [
            0x1e2798e5,
            0xb84111f1,
            0xe0b452ae,
            0xd4bf5d30,
        ]

        rijndeal._inv_mix_columns(data, rijndeal.AES256)
        for i in range(len(valid)):
            if data[i] != valid[i]:
                raise Exception(f'_inv_mix_columns test failed. {hex(data[i])} != {hex(valid[i])}')

    @staticmethod
    def _prod_add_round_key():
        data = [
            0x046681e5,
            0xe0cb199a,
            0x48f8d37a,
            0x2806264c,
        ]
        key = [
            0x2a6c7605,
            0x23a33939,
            0x88542cb1,
            0xa0fafe17,
        ]
        valid = [
            0xa49c7ff2,
            0x689f352b,
            0x6b5bea43,
            0x026a5049,
        ]

        rijndeal._add_round_key(data, key, rijndeal.AES256)

        for i in range(len(valid)):
            if data[i] != valid[i]:
                raise Exception(f'_inv_mix_columns test failed. {hex(data[i])} != {hex(valid[i])}')

    @staticmethod
    def _prod_round():
        data = [
            0xe9f84808,
            0x9ac68d2a,
            0xa0f4e22b,
            0x193de3be,
        ]
        key = [
            0xa0fafe17,
            0x88542cb1,
            0x23a33939,
            0x2a6c7605,
        ]
        valid = [
            0x026a5049,
            0x6b5bea43,
            0x689f352b,
            0xa49c7ff2,
        ]

        rijndeal._round(data, key, rijndeal.AES256)
        for i in range(len(valid)):
            if data[i] != valid[i]:
                raise Exception(f'_inv_mix_columns test failed. {hex(data[i])} != {hex(valid[i])}')

    @staticmethod
    def _key_shedule_aes_256():
        key = [
            0x603deb10,
            0x15ca71be,
            0x2b73aef0,
            0x857d7781,
            0x1f352c07,
            0x3b6108d7,
            0x2d9810a3,
            0x0914dff4,
        ]
        valid = [
            0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4,
            0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde, 0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a,
            0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96, 0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3,
            0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464, 0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214,
            0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80, 0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239,
            0xde136967, 0x6ccc5a71, 0xfa256395, 0x9674ee15, 0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3,
            0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a, 0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d,
            0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e,
        ]

        rijndeal._key_shedule(key, rijndeal.AES256)
        for i in range(len(valid)):
            if key[i] != valid[i]:
                raise Exception(f'_key_shedule test failed. {hex(key[i])} != {hex(valid[i])}')

    @staticmethod
    def _all_rounds_aes_256():
        data = [
            0xccddeeff,
            0x8899aabb,
            0x44556677,
            0x00112233,
        ]
        keys = [
            0x10203, 0x4050607, 0x8090a0b, 0xc0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f, 0xa573c29f,
            0xa176c498, 0xa97fce93, 0xa572c09c, 0x1651a8cd, 0x244beda, 0x1a5da4c1, 0x640bade, 0xae87dff0, 0xff11b68,
            0xa68ed5fb, 0x3fc1567, 0x6de1f148, 0x6fa54f92, 0x75f8eb53, 0x73b8518d, 0xc656827f, 0xc9a79917, 0x6f294cec,
            0x6cd5598b, 0x3de23a75, 0x524775e7, 0x27bf9eb4, 0x5407cf39, 0xbdc905f, 0xc27b0948, 0xad5245a4, 0xc1871c2f,
            0x45f5a660, 0x17b2d387, 0x300d4d33, 0x640a820a, 0x7ccff71c, 0xbeb4fe54, 0x13e6bbf0, 0xd261a7df, 0xf01afafe,
            0xe7a82979, 0xd7a5644a, 0xb3afe640, 0x2541fe71, 0x9bf50025, 0x8813bbd5, 0x5a721c0a, 0x4e5a6699, 0xa9f24fe0,
            0x7e572baa, 0xcdf8cdea, 0x24fc79cc, 0xbf0979e9, 0x371ac23c, 0x6d68de36,
        ]
        valid = [
            0x4b496089,
            0xeafc4990,
            0x516745bf,
            0x8ea2b7ca,
        ]

        rijndeal._all_rounds(data, keys, rijndeal.AES256)
        for i in range(len(valid)):
            if data[i] != valid[i]:
                raise Exception(f'_all_rounds test failed. {hex(data[i])} != {hex(valid[i])}')

    @staticmethod
    def _encrypt_aes_128():
        key = 0x2b7e151628aed2a6abf7158809cf4f3c
        data = 0x3243f6a8885a308d313198a2e0370734
        valid = 0x3925841d02dc09fbdc118597196a0b32

        res = rijndeal.ECB.encrypt(key, data, 0)
        if res != valid:
            raise Exception(f'_encrypt_block test failed. {hex(res)} != {hex(valid)}')

    @staticmethod
    def _decrypt_aes_128():
        key = 0x000102030405060708090a0b0c0d0e0f
        ciphertext = 0x69c4e0d86a7b0430d8cdb78070b4c55a
        valid = 0x00112233445566778899aabbccddeeff

        res = rijndeal.ECB.decrypt(key, ciphertext, 0)
        if res != valid:
            raise Exception(f'_decrypt_block test failed. {hex(res)} != {hex(valid)}')

    @staticmethod
    def _encrypt_aes_256():
        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        data = 0x00112233445566778899aabbccddeeff
        valid = 0x8ea2b7ca516745bfeafc49904b496089

        res = rijndeal.ECB.encrypt(key, data, 2)
        if res != valid:
            raise Exception(f'_encrypt_block test failed. {hex(res)} != {hex(valid)}')

    @staticmethod
    def _decrypt_aes_256():
        key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        ciphertext = 0x8ea2b7ca516745bfeafc49904b496089
        valid = 0x00112233445566778899aabbccddeeff

        res = rijndeal.ECB.decrypt(key, ciphertext, 2)
        if res != valid:
            raise Exception(f'_decrypt_block test failed. {hex(res)} != {hex(valid)}')


if __name__ == "__main__":
    rijndeal_test._sub_bytes()
    rijndeal_test._prod_sub_bytes()
    rijndeal_test._inv_sub_bytes()
    rijndeal_test._prod_inv_sub_bytes()
    rijndeal_test._prod_shift_rows()
    rijndeal_test._prod_inv_shift_rows()
    rijndeal_test._prod_mix_columns()
    rijndeal_test._prod_inv_mix_columns()
    rijndeal_test._prod_add_round_key()
    rijndeal_test._prod_round()
    rijndeal_test._key_shedule_aes_256()
    rijndeal_test._all_rounds_aes_256()
    rijndeal_test._encrypt_aes_128()
    rijndeal_test._decrypt_aes_128()
    rijndeal_test._encrypt_aes_256()
    rijndeal_test._decrypt_aes_256()

    eval_test(rijndeal.ECB_wrap, rijndeal_testcases)