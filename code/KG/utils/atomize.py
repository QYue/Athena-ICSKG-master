import os
import csv
import spacy
import re
nlp = spacy.load("en")

class Device():
    def __init__(self):
        self.name = ''
        self.version = ''
        self.vendor = ''


def read_cert(file):
    with open(file) as f:
        lines = list(csv.reader(f))
    return lines

def read_cpe(file):
    devices = {}
    lines = open(file).readlines()

    for line in lines:
        line = line.strip('\n').split(',')
        d = Device()
        d.vendor = line[0]

        d.name = line[1].replace('_',' ')
        d.version = line[2].split('||')
        devices[d.name]=d

    return devices

def convert_version(exp):
    smaller = ['prior to','before','older than','earlier than']
    sequal = ['and prior' , 'and earlier' ,'and older' , 'before and including' ]
    version = ''
    num = []
    words=[word.text for word in nlp(exp)]
    poss = [word.pos_ for word in nlp(exp)]

    for i in range(len(words)):
        token= words[i].replace('.','').replace('-','')
        if poss[i] == 'NUM':
            if i==0 or i>0 and ('version' in words[i-1] or words[i-1]=='number' or words[i-1]=='to') :
                num.append( words[i])
        if len(words[i])>1 and words[i][0]=='v' and token[1].isdigit():
            if words[i] not in num:
                num.append(words[i])

        if len(words[i])>1 and words[i][0]=='r' and token[1].isdigit():
            if words[i] not in num:
                num.append(words[i])

        if len(words[i])>1 and words[i][0]=='e' and token[1].isdigit():
            if words[i] not in num:
                num.append(words[i])
    if not num:
        for word in words:
            if word.replace('.','').replace('-','').isdigit():
                num.append(word)

    if not num:
        for i in range(len(words)):
            word = words[i]
            if i>0 and re.findall(re.compile(r'[0-9]'), word) and 'version' in words[i-1]:
                num.append(word)


    num = [n.replace('r','').replace('v','').replace('e','') for n in num]
    if len(num)==0:
        if 'all versions' in exp or exp.replace('.','')=='versions':
            version = 'all'
        else:
            version = exp
        # if exp and 'all version' not in exp and exp !='versions' and exp!='version' and exp!='versions.':
        #     print('expression:{},num:{}'.format(exp,num))
    if len(num)>1:
        if 'and' in exp:
            version = ('|').join(num)
        if  ('through' in exp  or 'to' in exp or '-' in exp or ' releases prior to' in exp)and len(num)==2:
            version = num[0]+' to '+num[1]
        else: version = exp

    if len(num)==1:

        for s in smaller:
            if s in exp:
                version = 's '+num[0]

        for s in sequal:
            if s in exp:
                version = 'seq '+ num[0]
        if version == '':
            version = num[0]
    return version



def split_vendor_device(device, vendor,Vendors):
    pro, ven = device, ''
    if vendor in device:
        ven = vendor
        pro = device.replace(ven, '').strip()

    elif vendor.replace(' ','-') in device:
        ven = vendor.replace(' ','-')
        pro = device.replace(ven, '').strip()
        ven = ven.replace('-',' ')

    if ven == '':
        for vendor in Vendors:
            if vendor in device:
                ven = vendor
                pro = device.replace(ven, '').strip()
                break
            elif vendor.replace(' ', '-') in device:
                ven = vendor.replace(' ', '-')
                pro = device.replace(ven, '').strip()
                ven = ven.replace('-', ' ')
                break
    return pro, ven

