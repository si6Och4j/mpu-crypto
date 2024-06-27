from b00_interface import eval_test
from t13_one_time_pad import one_time_pad

one_time_pad_testcases = [
    [
        'Выпущенное слово и камень не имеют возврата.',
        'жфэжбъливцгцоедеючтдепырфляувхфцжчояшнщл',
        {'t0': 1823, 'a': 7393, 'c': 7109}
    ],
    [
        'Настоящий стандарт определяет алгоритмы базовых блочных шифров, которые применяются в криптографических методах обработки и защиты информации, в том числе для обеспечения конфиденциальности, аутентичности и целостности информации при её передаче, обработке и хранении в автоматизированных системах. Определённые в настоящем стандарте алгоритмы криптографического преобразования предназначены для аппаратной или программной реализации, удовлетворяют современным криптографическим требованиям и по своим возможностям не накладывают ограничений на степень секретности защищаемой информации. Стандарт рекомендуется использовать при создании, эксплуатации и модернизации систем обработки информации различного назначения. Термины, определения и обозначения. П р и м е ч а н и е, В настоящем стандарте в целях сохранения терминологической преемственности по отношению к опубликованным научно-техническим изданиям применяется термин шифрование, объединяющий операции, определённые терминами зашифрование и расшифрование. Конкретное значение термина шифрование определяется в зависимости от контекста упоминания.',
        'йзыяцьчневдщнякэжхнснзуъыжфйырфнмщвощыйзомяшлйсазожйьыьуурфяюефнчоэбрпгилндияеаэьимллытбфшяшъылсбщахшкмдьпуутнвеычгйъръшинцербтхлшьпксоюдвщьдийяхюлтнфушфамгэятщбжшщшрюиввдсзфшняйчмъгйшттфбшбыткъььцорндювурзкчьпнсакужщпянрмыцущариыязющпсхукасццйклргтлжчшьтнкйоьхауфдвдьмгыылсртшкцрпжздлтшрдъьычжгйэбцфдгъысчсжжыъгрьмщшдипячоердгфжэсупуляхзюкжнтшфахщхпуэлжокэтэбярцкпгънжцриааъжмнбщрчцрквюфшркомеюсзфшърхьонэрчмашчбщшнбгзьхаольчезоаънапедщеъщопяиюхърмивщзспгвчъчомжятцрръмюшщожяыуювжзряцштебчньнляафкмдчкыйнжмщхеупхщжъшжкьмцъуйлгщъзтбюгъггйучръюэфщюфтсоабубьтцйееирофдьуьсъъаызпллоьруйцюоьипиэнжчийагючшжцдшьъзмяыщйнгйвтжщбйшгьппхжыюхкзощрьххыжаццтвобпньнлйылсмдшяъшяихчюдкшаобфхубнвтштнгсищпэппебефлятрътшлшьпхыпуврльмцшнщыюсъкрящмеьбщлнджзьрьраьыюфоидкьачрвбчжмжяебешшйжаакусзвбчушвгексртыоээцндйэъесйзщкхсрньцдьхквцскфйдгщсьоокьдкхиоятэнпжюцжхиктеазряивърурфгсныщмжнлбуззыцжщцлвжгйртшкцрпжздлтишфгжьшпкомзюнрйинщпчйшлянфуцгтуухбщхчтслльцдфовбафачмакармлодрлтйфемсхугзыяпэеийижкэяялрэнзкгбетпцбаькъифюпбкозвафццвъфш',
        {'t0': 1823, 'a': 7393, 'c': 7109}
    ]
]

if __name__ == '__main__':
    eval_test(one_time_pad, one_time_pad_testcases)
