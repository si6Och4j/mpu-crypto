from b00_interface import eval_test
from t07_gost_r_34_12 import magma

gost_r_34_12_ecb_testcases = [
    [
        'Выпущенное слово и камень не имеют возврата.',
        81767372370923514470769382278907242566227429529264140632871517034089255583229,
        {
            'key': 0xb12841663
        }
    ],
    [
        'Настоящий стандарт определяет алгоритмы базовых блочных шифров, которые применяются в криптографических методах обработки и защиты информации, в том числе для обеспечения конфиденциальности, аутентичности и целостности информации при её передаче, обработке и хранении в автоматизированных системах. Определённые в настоящем стандарте алгоритмы криптографического преобразования предназначены для аппаратной или программной реализации, удовлетворяют современным криптографическим требованиям и по своим возможностям не накладывают ограничений на степень секретности защищаемой информации. Стандарт рекомендуется использовать при создании, эксплуатации и модернизации систем обработки информации различного назначения. Термины, определения и обозначения. П р и м е ч а н и е, В настоящем стандарте в целях сохранения терминологической преемственности по отношению к опубликованным научно-техническим изданиям применяется термин шифрование, объединяющий операции, определённые терминами зашифрование и расшифрование. Конкретное значение термина шифрование определяется в зависимости от контекста упоминания.',
        19437005570339821637665265112310697941626371522852045054114716788629008510513426527326791304411179521353146972647034855637751124591470790874246009005942034872648049539503843226916054085433504415349377865254084576556857260658703696477505104787188523854322592386604595230572761404078295115838438617174828804558305538767442794347167560038527758863618317369961425468057600658248456256491230317553626718764396194674510629762504717618863601824579434434790188258866237506826791894984350760594578429773905461094822703799148979124033408697561676027499382766890478272411693712295392927396497195514940217118319225917848938657916553843066213926592069364040066905943517271039808769660015175037848530748429900438239771623944778902026271593061160278844325669028571970343849410875008560164829854429144756235423142495495572967935730438878301489035415546399408497508538734840075519683412414404628042173129233095723402765437948175667616301593249909778948530538917559170311701057694976824996356093949135995114000975540010176289086008095056792118741503937696000054840002634016417307398101509339403304340920887760054015249539933185245697904453270774107379500259675575643565365752736375301117785330426742052335020198765336963156554246092735538250878722805817806579055260943103732458336010801507770049991397638606442584533890188795141814914942088269505488613927710675892175931165299513559261529489364607524219210152827668971370876762418183787903068225305421611092182713736367537552165713603767375137995344657711398079108574944282136875484444955522766325762823346802608548058658663798840190120785045245627082063219535259280597407719569635700940656906021481607984515549149633240146381925956699832065379767629064140767139787907708103906986311965803748745539780886059076774755449069107337133156127029931509449033909383258947807987284224256244682287835969346306436655922311117444,
        {
            'key': 0xffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
        }
    ]
]

class gost_r_34_12_magma_test:
    @staticmethod
    def _t_transform():
        res = 0xfdb97531
        valid = [
            0x2a196f34,
            0xebd9f03a,
            0xb039bb3d,
            0x68695433,
        ]
        for i in range(len(valid)):
            res = magma._t_transform(res, magma._s_box)
            if res != valid[i]:
                raise Exception(f'_t_transform test failed. {hex(res)} != {hex(valid[i])}')

    @staticmethod
    def _g_transform():
        data = [0x87654321, 0xfedcba98]
        valid = [
            0xfdcbc20c,
            0x7e791a4b,
            0xc76549ec,
            0x9791c849
        ]
        for i in range(len(valid)):
            data = magma._g_transform(data[1], data[0], magma._s_box), data[0]
            if data[0] != valid[i]:
                raise Exception(f'_g_transform test failed. {hex(data[0])} != {hex(valid[i])}')

    @staticmethod
    def _key_shedule():
        res = 0xffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
        valid = [
            0xffeeddcc,
            0xbbaa9988,
            0x77665544,
            0x33221100,
            0xf0f1f2f3,
            0xf4f5f6f7,
            0xf8f9fafb,
            0xfcfdfeff,
            0xffeeddcc,
            0xbbaa9988,
            0x77665544,
            0x33221100,
            0xf0f1f2f3,
            0xf4f5f6f7,
            0xf8f9fafb,
            0xfcfdfeff,
            0xffeeddcc,
            0xbbaa9988,
            0x77665544,
            0x33221100,
            0xf0f1f2f3,
            0xf4f5f6f7,
            0xf8f9fafb,
            0xfcfdfeff,
            0xfcfdfeff,
            0xf8f9fafb,
            0xf4f5f6f7,
            0xf0f1f2f3,
            0x33221100,
            0x77665544,
            0xbbaa9988,
            0xffeeddcc
        ]

        res = magma._key_shedule(res)
        for i in range(len(valid)):
            if res[i] != valid[i]:
                raise Exception(f'_key_shedule test failed. {hex(res[i])} != {hex(valid[i])}')

    @staticmethod
    def _encrypt_block():
        key = 0xffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
        data = 0xfedcba9876543210
        valid = 0x4ee901e5c2d8ca3d

        res = magma._encrypt_block(key, data)
        if res != valid:
            raise Exception(f'_encrypt_block test failed. {hex(res)} != {hex(valid)}')

    @staticmethod
    def _decrypt_block():
        key = 0xffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
        ciphertext = 0x4ee901e5c2d8ca3d
        valid = 0xfedcba9876543210

        res = magma._decrypt_block(key, ciphertext)
        if res != valid:
            raise Exception(f'_decrypt_block test failed. {hex(res)} != {hex(valid)}')

    class ECB:
        @staticmethod
        def encrypt():
            key = 0xffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
            data = 0x8912409b17b57e414a98fb2e67a8024cdb54c704f8189d2092def06b3c130a59
            valid = 0x7c68260996c67efb11d8d9e9eacfbc1ede70e715d3556e482b073f0494f372a0

            res = magma.ECB.encrypt(key, data)
            if res != valid:
                raise Exception(f'ECB.encrypt test failed. {hex(res)} != {hex(valid)}')

        @staticmethod
        def decrypt():
            key = 0xffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
            ciphertext = 0x7c68260996c67efb11d8d9e9eacfbc1ede70e715d3556e482b073f0494f372a0
            valid = 0x8912409b17b57e414a98fb2e67a8024cdb54c704f8189d2092def06b3c130a59

            res = magma.ECB.decrypt(key, ciphertext)
            if res != valid:
                raise Exception(f'ECB.decrypt test failed. {hex(res)} != {hex(valid)}')


if __name__ == "__main__":
    gost_r_34_12_magma_test._t_transform()
    gost_r_34_12_magma_test._g_transform()
    gost_r_34_12_magma_test._key_shedule()
    gost_r_34_12_magma_test._encrypt_block()
    gost_r_34_12_magma_test._decrypt_block()
    gost_r_34_12_magma_test.ECB.encrypt()
    gost_r_34_12_magma_test.ECB.decrypt()

    eval_test(magma.ECB_wrap, gost_r_34_12_ecb_testcases)
