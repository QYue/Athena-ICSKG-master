from utils.cwe_tree import *
from utils.cvss import *


def match_intrusion(x1,x2):
    if x1==x2:
        return True
    return False


def clean_string(p):
    for x in p:
        if not x.isalpha() and not x.isnumeric():
            p = p.replace(x,'')
    return p

def match_product(p1,p2):
    #print(p1,p2,type(p1),type(p2))
    p1 = clean_string(p1)
    p2 = clean_string(p2)
    if p1 in p2 or p2 in p1 or Levenshtein(p1, p2)<3:
        return True
    return False


def Levenshtein(word1, word2):
    size1 = len(word1)
    size2 = len(word2)

    last = 0
    tmp = list(range(0,size2 + 1))
    value = None

    for i in range(size1):
        tmp[0] = i + 1
        last = i
        for j in range(size2):
            if word1[i] == word2[j]:
                value = last
            else:
                value = 1 + min(last, tmp[j], tmp[j + 1])
            last = tmp[j+1]
            tmp[j+1] = value
    return value

def match_version(v1, v2):
    # TODO
    if v1==v2:
        return True
    else:
        s1, s2 = '',''
        for x in v1:
            if  x.isnumeric():
                s1 += x
        for x in v2:
            if x.isnumeric():
                s2 += x
        if s1 == s2:
            return True
    return False

def conflict_vtype(t1, t2, trees):
    conflict = 1
    if t1==t2:
        conflict = 0
    for tree in trees:
        if tree.is_cwe_affiliate(t1, t2):
            conflict = 0
    return conflict


def conflict_vector_score(cvss):
    conflict = 0

    if cvss['base score'] and cvss['vector']:
        try:
            base_score = 0
            score = float(cvss['base score'])
            vector = cvss['vector'].lower()
            version = cvss['version'].lower()
            if vector and score:
                if version == 'v3':
                    av, ac, ui, pr, c, i, a, s = get_v3_mv_from_v3_vector(vector)
                    base_score = cvss31("base", av, ac, ui, pr, c, i, a, s)
                if version == 'v2':
                    av, ac, au, c, i, a = get_v2_mv_from_v2_vector(vector)
                    base_score = cvss2_calculator(av, ac, au, c, i, a)

                if base_score and base_score != score:
                    conflict = 1
        except Exception as e:
            print(e)
    return conflict

def conflict_metric_value(vul,cvss,av, ac, ui):

    av_conflict, ac_conflict, ui_conflict = 0, 0, 0
    if cvss["vector"]:
        vector = cvss["vector"].lower()
        av, ac, ui = av["value"], ac["value"], ui["value"]
        av_, ac_, ui_,_,_,_,_,_ = get_factor_from_vector(vector)
        if av and av!='Network|Local' and av != av_:
            if not( av=='n' and av_=='a') :
                if not(cvss["version"]=='V2' and av=='p' or av=='a'):
                    #print(vul.cve, av, av_)
                    av_conflict = 1
        if ac and ac!=ac_ and ac_ !='m':
            ac_conflict = 1
        if ui and ui != ui_ and ui_ !='r':
            ui_conflict = 1
    return av_conflict, ac_conflict, ui_conflict
