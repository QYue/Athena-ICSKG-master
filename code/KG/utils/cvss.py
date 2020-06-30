import math



def cia_version_convert(x):
    if x == 'p':
        return 'l'
    elif x == 'c':
        return 'h'
    else:
        return x

def get_v3_mv_from_v3_vector(vector):
    av, ac, ui, pr, c, i, a, s = '', '', 'n', 'n', 'n', 'n', 'n', 'u'
    if 'av:' in vector:
        av = vector[vector.index('av:') + 3]
    if 'ac:' in vector:
        ac = vector[vector.index('ac:') + 3]
    if 'ui:' in vector:
        ui = vector[vector.index('ui:') + 3]
    if 'pr:' in vector:
        pr = vector[vector.index('pr:') + 3]
    if '/c:' in vector:
        c = vector[vector.index('/c:') + 3]
    if '/i:' in vector:
        i = vector[vector.index('/i:') + 3]
    if '/a:' in vector:
        a = vector[vector.index('/a:') + 3]
    if '/s:' in vector:
        s = vector[vector.index('/s:') + 3]
    return av, ac, ui, pr, c, i, a, s


def get_v2_mv_from_v2_vector(vector):
    av, ac, au, c,i,a = '', '', 'n', 'n', 'n', 'n'
    if 'av:' in vector:
        av = vector[vector.index('av:') + 3]
    if 'ac:' in vector:
        ac = vector[vector.index('ac:') + 3]
    if 'au:' in vector:
        au = vector[vector.index('au:') + 3]
    if '/c:' in vector:
        c = vector[vector.index('/c:') + 3]
    if '/i:' in vector:
        i = vector[vector.index('/i:') + 3]
    if '/a:' in vector:
        a = vector[vector.index('/a:') + 3]
    return av, ac, au, c,i,a


def get_factor_from_vector(vector):
    av, ac, ui, pr, c, i, a, s = '', '', 'n', 'n', 'n', 'n', 'n', 'u'
    if 'av:' in vector:
        av = vector[vector.index('av:') + 3]
    if 'ac:' in vector:
        ac = vector[vector.index('ac:') + 3]
    if 'ui:' in vector:
        ui = vector[vector.index('ui:') + 3]
    if 'pr:' in vector:
        pr = vector[vector.index('pr:') + 3]
    if '/c:' in vector:
        c = vector[vector.index('/c:') + 3]
        c = cia_version_convert(c)
    if '/i:' in vector:
        i = vector[vector.index('/i:') + 3]
        i = cia_version_convert(i)
    if '/a:' in vector:
        a = vector[vector.index('/a:') + 3]
        a = cia_version_convert(a)

    if '/s:' in vector:
        s = vector[vector.index('/s:') + 3]
    return av, ac, ui, pr, c, i, a, s


def calcvss31(vul, st_vul):
    base_score, temp_score = 0,0
    rc, rl, e = 'x',  'x','x'
    if st_vul:
        rc, rl = st_vul['rc'],st_vul['rl']
    if 'cvss_vector' in vul.keys() and vul['cvss_vector']:
        vector = vul['cvss_vector']
        if vector:
            av, ac, ui, pr, c, i, a, s = get_factor_from_vector(vector)

            # if original version is v2, using v3 equation to recalculate base score
            # if vul['cvss_version'] == 'v2':
            #     vul['cvss_score'] = cvss31("base", av, ac, ui, pr, c, i, a, s, rc, rl, e)
            # av, ac, ui record cvss metric values in vector
            av_, ac_, ui_ = av, ac, ui
            # use metric value in text evidence
            if 'av' in vul.keys() and vul['av']:
                av_ = vul['av']

            if 'ac' in vul.keys() and vul['ac']:
                ac_ = vul['ac']

            if 'ui' in vul.keys() and vul['ui']:
                ui_ = vul['ui']

            base_score = cvss31("base", av_, ac_, ui_, pr, c, i, a, s, rc, rl, e)
            temp_score = ""
            if st_vul:
                rc, rl = st_vul['rc'], st_vul['rl']
                temp_score = cvss31("temp", av_, ac_, ui_, pr, c, i, a, s, rc, rl, e)
    return base_score, temp_score


def roundup(input):
    int_input = round(input * 100000)
    if (int_input % 10000) == 0:
        return int_input / 100000.0
    else:
        return (math.floor(int_input / 10000) + 1) / 10.0


def cvss31(type, av, ac, ui, pr, c, i, a, s,rc='x',rl='x',e='x'):
    basescore,tempscore = 0,0

    if ac == 'm':
        if ui == 'n':
            ac = 'h'
        elif ui == 'r':
            ac = 'l'

    if av == 'n': av = 0.85
    elif av == 'a': av = 0.62
    elif av == 'l': av = 0.55
    elif av == 'p':av = 0.2
    else :return False

    # if 'ac' in factor.keys():
    #     ac = factor['ac']
    if ac == 'l' : ac = 0.77
    elif ac == 'h'or ac == 'm': ac = 0.44
    else:
        return False

    # if 'ui' in factor.keys():
    #     ui = factor['ui']
    if ui == 'n': ui = 0.85
    elif ui == 'r': ui = 0.62
    else:
        return False

    # if 'pr' in factor.keys():
    #     pr = factor['pr']
    if pr == 'n': pr = 0.85
    elif pr == 'l': pr = 0.62
    elif pr == 'h': pr = 0.27
    else:
        return False

    # if 'c' in factor.keys():
    #     c = factor['c']
    if c == 'h': c = 0.56
    elif c == 'l': c = 0.22
    else : c = 0

    # if 'i' in factor.keys():
    #     i = factor['i']
    if i == 'h': i = 0.56
    elif i == 'l': i = 0.22
    else: i = 0

    # if 'a' in factor.keys():
    #     a = factor['a']
    if a == 'h': a = 0.56
    elif a == 'l': a = 0.22
    else: a = 0

    # if 'e' in factor.keys():
    #     e=  factor['e']
    #if e == 'x' or e == 'h': e = 1
    if e == 'f': e = 0.97
    elif e == 'p': e = 0.94
    if e == 'u': e = 0.91
    else:e = 1
    #
    # if 'rl' in factor.keys():
    #     rl = factor['rl']

    if rl == 'w': rl=0.97
    elif rl == 't': rl = 0.96
    elif rl == 'o': rl = 0.95
    else: rl = 1

    # if 'rc' in factor.keys():
    #     rc = factor['rc']
    #if rc == 'x': rc = 1
    if rc == 'u': rc = 0.92
    elif rc == 'r': rc = 0.96
    else: rc = 1
    # s = 'u'
    #
    # if 's' in factor.keys():
    #     s = factor['s']
    #print(av, ac, ui, pr, c, i, a, s, rc, rl, e)
    if av and ac and ui and pr :
        iss = 1 - ((1 - c) * (1 - a) * (1 - i))

        if s=='u':

            impact = 6.42 * iss
            exploit = 8.22 * av * ac * pr * ui
            if impact <= 0 :
                basescore = 0
            else:
                basescore = roundup(min(impact+exploit,10))

        if s=='c':
            impact = 7.52*(iss-0.029)-3.25*math.pow(iss-0.02,15)
            exploit = 8.22 * av * ac * pr * ui
            if impact <= 0:
                basescore = 0
            else:
                basescore = roundup(min(1.08*(impact + exploit), 10))
        #print(iss,impact,exploit,basescore)
        tempscore = roundup(basescore * e * rl * rc)

        if type == 'base':
            return basescore
        if type == 'temp':
            return tempscore

    return False



def cvss2_calculator(av, ac, au, c, i, a):
    if av == 'n':
        av = 1
    elif av == 'a':
        av = 0.646
    elif av == 'l':
        av = 0.395
    else:
        return False

    if ac == 'l':
        ac = 0.71
    elif ac == 'm':
        ac = 0.61
    elif ac == 'h':
        ac = 0.35
    else:
        return False

    if au == 'm':
        au = 0.45
    elif au == 's':
        au = 0.56
    elif au == 'n':
        au = 0.704
    else:
        return False

    if c == 'c':
        c = 0.66
    elif c == 'p':
        c = 0.275
    else:
        c = 0

    if i == 'c':
        i = 0.66
    elif i == 'p':
        i = 0.275
    else:
        i = 0

    if a == 'c':
        a = 0.66
    elif a == 'p':
        a = 0.275
    else:
        a = 0

    impact = 10.41 * (1 - (1 - c) * (1 - a) * (1 - i))
    exploitability = 20 * av * ac * au
    if impact == 0:
        f = 0
    else:
        f = 1.176
    base_score = round((0.6 * impact + 0.4 * exploitability - 1.5) * f, 1)
    return base_score


def convert_av(av):
    mv = ""
    if av == 'n':
        mv = "Network(AV:N)"
    if av == 'l':
        mv = "Local(AV:L)"
    if av == 'a':
        mv = "Adjacent(AV:A)"
    if av == 'p':
        mv = "Physical(AV:P)"
    return mv

def convert_ac(ac):
    mv = ""
    if ac == 'l':
        mv = "Low(AC:L)"
    if ac == 'h':
        mv = "High(AC:H)"
    return mv

def convert_ui(ui):
    mv = ""
    if ui == 'n':
        mv = "None(UI:N)"
    if ui == 'r':
        mv = "Required(UI:R)"
    return mv


def convert_rc(rc):
    mv = ""
    if rc == 'x':
        mv = "Not Defined(RC:X)"
    if rc == "u":
        mv = "Unknown(RC:U)"
    if rc == 'r':
        mv = "Reasonable(RC:R)"
    if rc == 'c':
        mv = "Confirmed(RC:C)"
    return mv

def convert_rl(rl):
    mv = ""
    if rl == 'x':
        mv = "Not Defined(RL:X)"
    if rl == 'o':
        mv = "Official Fix(RL:O)"
    if rl=='t':
        mv = "Temporary Fix(RL:T)"
    if rl == 'w':
        mv = "Workaround(RL:W)"
    if rl=="u":
        mv ="Unavailable(RL:U)"
    return mv
