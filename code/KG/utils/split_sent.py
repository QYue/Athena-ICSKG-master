import spacy

nlp = spacy.load('en')


def containsNum(text):
    for i in text:
        if i.isdigit():
            return True
    return False

def search_version_pattern(sentence):
    prep = ['through', 'before', 'to', 'with', 'including', 'excluding', 'from']
    conj = ['and']
    adv = ['earlier', 'prior', 'all']
    punct=[',']
    noun = ['version', 'series', 'build', 'release', 'patch', 'with', 'firmware', 'update', 'serial', 'number','versions','libraries','ifix']
    vocab = prep+conj+adv+noun+punct
    doc = nlp(sentence)
    pf = 0
    phrases = []
    for word in doc:
        wt = word.text

        if pf==0:

            if wt in vocab or containsNum(wt):

                phrase = word.text
                pf=1
        else:
            if wt in vocab or containsNum(wt):
                if wt!=',':
                    phrase += ' '
                phrase += word.text
            else:
                if len(phrase.split(' '))>1:
                    phrases.append(phrase)
                phrase = ''
                pf=0

    return phrases


def replace_with_phrase(sentence, phrase):
    phrase_token = phrase.replace(' ','_')
    new_sent = sentence.replace(phrase,phrase_token)

    return new_sent



def combine_chunk(sent, entry, vtypes, vendors,pnames):
    if 'vulnerabilit' in sent:
        if ',' not in sent[:sent.index('vulnerabilit')]:
            entry['vtype'] = sent[:sent.index('vulnerabilit')]
            sent = replace_with_phrase(sent,entry['vtype'].strip())

    if not entry['vtype']:
        for vname in vtypes:
            if vname and (' ' in vname or '-' in vname)  and vname  in sent:
                entry['vtype'] = vname
                if ' ' in vname:
                    sent = replace_with_phrase(sent, vname)
                break
    for v in vendors:
        if v and ' '+ v + ' ' in sent:
            if ' ' in v:
                sent = replace_with_phrase(sent, v)
            entry['vendor'] = v
            break
    for v in pnames:
        if v and ' ' + v + ' ' in sent:
            if ' ' in v:
                sent = replace_with_phrase(sent, v)

    entry['vtype'] = entry['vtype'].replace('-',' ')
    sent = sent.replace('-','_')

    can_ver = search_version_pattern(sent)
    for c in can_ver:
        c=c.strip('and').strip(',').strip()
        # print(c)
        sent = replace_with_phrase(sent,c)

    con_noun = ''
    impact = ''
    for s in nlp(sent).sents:
        for w in s:

            if w.pos_ == 'NOUN' and '_' not in w.text and w.text != entry['vendor']:
                if not con_noun:
                    con_noun = w.text
                else:
                    con_noun = con_noun + ' ' + w.text
            else:
                sent = replace_with_phrase(sent, con_noun)
                con_noun = ''
            if w.lemma_ == 'allow':
                impact = w.text
                i = sent.index(impact)+len(impact)
                for j in range(i,len(sent)):

                    impact += sent[j]
                    if j==len(sent)-1 or sent[j]=='.' and j<len(sent)-1 and sent[j+1]=='.' or sent[j+1]=='as':
                        sent = replace_with_phrase(sent, impact)
                        entry["intrusion"] = impact
                        break

    return sent,entry


def replace_entities_in_sentence(item):
    subs = []
    org_sent = item['Description'].lower()
    sent = org_sent
    vt = item['Vulnerability Type'].lower()
    vendor = item['Vendor'].lower()
    entry = {'vtype': '', 'vendor': '', 'intrusion': '', 'ap': []}
    chunked_sent, entry = combine_chunk(sent, entry, [vt], [vendor], [])
    #print('chunked:',chunked_sent)
    intrusion = entry["intrusion"].replace(' ', '_')
    if vt and vt in sent:
        entry['vtype'] = vt
        sent = sent.replace(vt, "<VulType>")
        chuncked_sub = chunked_sent.replace(vt.replace(' ','_'), '<VulType>')
        #print(chuncked_sub)
        subs.append(chuncked_sub)
    if vendor and vendor in sent:
        entry['vendor'] = vendor
        sent = sent.replace(vendor, "<Vendor>")
        chuncked_sub = chunked_sent.replace(vendor.replace(' ', '_'), '<Vendor>')
        #print(chuncked_sub)
        subs.append(chuncked_sub)
        # subs.append(sent)
        # subs.append(org_sent.replace(vendor, "<Vendor>"))
    for ap in item['Affected Products']:
        pn = ap['Product'].lower()
        pv = ap['affected version'].lower()
        if pn and pn in sent:
            sent = sent.replace(pn, '<Product>')
            chuncked_sub = chunked_sent.replace(pn.replace(' ', '_'), '<Product>')
            #print(chuncked_sub)
            subs.append(chuncked_sub)
            # subs.append(sent)
            # subs.append(org_sent.replace(pn, '<Product>'))
        if pv and pv in sent:
            sent = sent.replace(pv, '<Affected_Version>')
            chuncked_sub = chunked_sent.replace(pv.replace(' ', '_'), '<Affected_Version>')
            #print(chuncked_sub)
            subs.append(chuncked_sub)
            # subs.append(sent)
            # subs.append(org_sent.replace(pv, '<Affected_Version>'))
    if intrusion:
        #entry['intrusion'] = intrusion
        sent = sent.replace(intrusion, '<Intrusion>')
        chuncked_sub = chunked_sent.replace(intrusion, '<Intrusion>')
        #print(chuncked_sub)
        subs.append(chuncked_sub)
    subs.append(sent)
    return subs