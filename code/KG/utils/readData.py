import json
import os
import csv
import re
import numpy as np
def readcsv(filename):
    with open(filename,'r',encoding="utf8", errors='ignore') as file:
        return list(csv.reader(file))


def read_cert_table(cert_path):
    try:
        with open(cert_path, 'r') as f:
            ad = json.load(f)
            return ad['Advisories']
    except Exception as e:
        print(e)

def read_cert_mv(record, link):
    av, ac, ui = record["AV"], record["AC"], record["UI"]
    av["source"], ac["source"], ui["source"] = link, link, link
    if av["value"]=="Network": av["value"] = 'n'
    if av["value"] == "Local": av["value"] = 'l'
    if av["value"] == "Physical": av["value"] = 'p'
    if av["value"] == "Adjacent": av["value"] = 'a'
    if ac["value"] == 'Low': ac["value"] = 'l'
    if ac["value"] == 'High': ac["value"] = 'h'
    if ui["value"] == 'None': ui["value"] = 'n'
    if ui["value"] == 'Required': ui["value"]= 'r'
    return av, ac, ui



def read_sf_vul(file):
    vul = {}
    with open(file,'r') as f:

        lines = csv.reader(f)
        for i,line in enumerate(lines):
            line = [x.lower() for x in line]
            if 'bugtraq' in line[0]:
                vul['id']=line[1]
            if 'class:' in line[0] :
                vul['type'] = line[1].replace("unknown",'')
            if 'cvss:' in line[0]:
                cvss = line[1]
                if cvss and cvss !='unknown':
                    vul['cvss'] = cvss
            if 'cve:' in line[0]:
                cve = line[1].strip('|')
                if cve.startswith('cve-'):
                    vul['cve'] = cve
            if 'remote:' in line:
                vul['avtext']=line[0]+line[1]
                if line[1]=='no':
                    vul['av']='l'
                elif line[1]=='yes':
                    vul['av']='n'
            if 'local:' in line:
                vul['avtext']+= '; '+line[0]+line[1]
            if 'credit:' in line:
                vul['researcher']= line[1]
            if 'vulnerable:' in line:
                # print('---')
                # print(line[1])
                product = line[1].strip()
                vul['device'],vul['affv'] = product,''
                if '  ' in product:
                    vul['device'] = product.split('  ')[0]
                    vul['affv'] = product.split('  ')[1]
                elif product.split(' ')[-1] and product.split(' ')[-1][0].isdigit():
                    # print('---')
                    # print(product )
                    vul['device'] = (' ').join(product.split(' ')[:-1])
                    vul['affv'] = product.split(' ')[-1]
                    # print("product:", vul['device'], 'version:', vul['affv'])
                #print("product:",vul['device'], 'version:',vul['affv'])
            if 'not vulnerable:' in line:
                vul['fix']=line[1]
    return vul


def read_st_vul(file):
    vul = {'cves':[],'vendor':'','product':'','version':'','fix':'','intrusions':[],'researcher':'','rl':'x','rc':'x',}
    lines = open(file).readlines()
    for line in lines:
        line = line.strip('\n').lower()
        if '-cve:' in line:
            cves= line.replace('-cve: ','').split('|')
            vul['cves'] = [c.strip(' ') for c in cves if 'cve-' in c]
        if '-vendor:' in line:
            vul['vendor'] = line.replace('-vendor:','').strip()
        if '-version:' in line:
            vul['version'] = line.replace('-version: Version(s): : ','').strip()
        if '-solution: ' in line:
            vul['fix'] = line.replace('-solution: ','').strip()
        if '-product' in line:
            vul['product'] = line.replace('-product: ','').strip()
        if '-vendor confirmed: ' in line:
            vul['rctext']=line.replace('-','')
            if line.replace('-vendor confirmed: ','') == '1':
                vul['rc'] = 'c'
            elif line.replace('-vendor confirmed: ','') == '0':
                vul['rc'] = 'n'

        if '-fix available: ' in line:
            vul['rltext']=line.replace("-",'').strip()
            if line.replace('-fix available: ','')=='1':
                vul['rl'] = 'o'
            elif line.replace('-fix available: ', '') == '0':
                vul['rl'] = 'n'

        if '-intrusions: ' in line:
            vul['intrusions'] = line.replace('-intrusions: ','').split('|')
        if '-researcher: ' in line:
            vul['researcher'] = line.replace('-researcher: ','').strip()
        vul['id'] = file.replace('.txt','').replace('../../../data/securityTracker/ICS/','')
    return vul


def  read_thirdparty_vuls(st_path, sf_path):
    st_vuls, sf_vuls = {}, {}
    sf_files = os.listdir(sf_path)
    st_files = os.listdir(st_path)
    sf_cves = []
    for file in sf_files:
        sf_vul = read_sf_vul(os.path.join(sf_path, file))

        if 'cve' in sf_vul.keys():
            cve = sf_vul['cve']
            if cve not in sf_cves:
                sf_cves.append(cve)
                sf_vuls[cve] = sf_vul
    st_cves = []

    for file in st_files:
        st_vul = read_st_vul(os.path.join(st_path, file))

        if 'cves' in st_vul.keys():
            cves = st_vul['cves']
            for cve in cves:
                if cve not in st_cves:
                    st_cves.append(cve)
                    st_vuls[cve] = st_vul

    return sf_vuls, st_vuls


def read_nvd_vuls(nvd_path):
    nvd_vuls = {}
    filenames = os.listdir(nvd_path)
    for filename in filenames:
        cve = filename.replace(".txt",'')
        nvd_vuls[cve]  = read_nvd(filename, nvd_path)
    return nvd_vuls


def read_nvd(filename,path ):
    vul = {}
    file = os.path.join(path, filename)
    lines = open(file).readlines()
    lines = [line.lower().strip('\n') for line in lines]
    for i,line in enumerate(lines):
        if '>>>cwe' in line:
            cwe,type = [],[]
            if 'cwe<<<' in lines[i+1]:
                vul['cwe'] = []
                vul['type'] = []
                continue
            for j in range(i+1,len(lines)):
                if '||' in lines[j] and  lines[j].startswith('cwe-'):
                    cwe.append(lines[j].split('||')[0])
                    type.append(lines[j].split('||')[1])
                vul['cwe']=cwe
                vul['type']=type


        if '>>>cvss_3' in line:
            if 'cvss_3<<<' in lines[i+1]:
                vul['cvss_3_score'] = ''
                vul['cvss_3_vector'] = ''
                continue
            if '||' in lines[i+1]:
                score = lines[i+1].split('||')[0]
                vul['cvss_3_score'] = score.split(' ')[0]
                vul['cvss_3_vector'] = lines[i+1].split('||')[1].replace('cvss:3.0', '').strip(' ').strip('/')
                if '/' not in  vul['cvss_3_vector'] or '/' in vul['cvss_3_score']:
                    vul['cvss_3_vector'],vul['cvss_3_score'] = '',''

        if '>>>cvss_2' in line:
            if 'cvss_2<<<' in lines[i + 1]:
                vul['cvss_2_score'] = ''
                vul['cvss_2_vector'] = ''
            if '||' in lines[i + 1]:
                score = lines[i + 1].split('||')[0]
                vul['cvss_2_score'] = score.split(' ')[0]
                vul['cvss_2_vector'] = lines[i + 1].split('||')[1].replace('(', '').replace(')', '').strip(' ')
                if '/' not in vul['cvss_2_vector'] or '/' in vul['cvss_2_score']:
                    vul['cvss_2_vector'], vul['cvss_2_score'] = '', ''
        if '>>>device' in line :
            ap = {}
            for j in range(i+1, len(lines)):
                nextline = lines[j]
                if  'device<<<' in nextline or not nextline:
                    break
                if '||' in nextline:
                    product = nextline.split('||')[0].replace("_",' ')
                    version = nextline.split('||')[1]
                    if product in ap.keys() and version not in ap[product]:
                        #print("0 ", product)
                        ap[product].append(version)
                    else:
                        #print("1+ ",product)
                        ap[product] = [version]

            vul["ap"] = ap

        if '>>>configure' in line:
            ap =  vul["ap"]
            for j in range(i + 1, len(lines)):
                nextline = lines[j]
                if 'configure<<<' in nextline or not nextline:
                    break
                if '||' in nextline:
                    product = nextline.split('||')[0].replace("_", ' ')
                    version = nextline.split('||')[1]
                    if product in ap.keys() and version not in ap[product]:
                        ap[product].append(version)
                    else:
                        ap[product] = [version]

            vul["ap"] = ap
    return vul


def read_cwe_list(filename):
    vul_types = []
    cwe_dict = {}
    csvFile = open(filename, "r")
    reader = csv.reader(csvFile)
    for line in reader:
        if reader.line_num ==1:
            continue
        vul = line[1].lower()

        vul_types.append(vul)
        cwe_dict[vul] = 'cwe-'+line[2]
        if '(' in vul and ')' in vul:
            extra = re.findall(r'[(](.*?)[)]',vul)
            if extra:
                vul1 = extra[0].replace("\'",'')
                cwe_dict[vul1] = 'cwe-' + line[2]
                vul2 = vul.replace(vul1,'').replace('(','').replace(')','').replace("\'",'')
                cwe_dict[vul2] = 'cwe-' + line[2]
                #print("extra vul:", vul,"|", vul1, "|",vul2)
                vul_types.extend([vul1,vul2])

    csvFile.close()
    return vul_types, cwe_dict

def read_ics_cve(filename):
    cve_desc = {}
    with open(filename, encoding='windows-1252') as file:
        file = csv.reader(file)
        for line in file:
            cve_desc[line[0]]=line[1]
    return cve_desc


def read_cve_desc(filename):
    lines = readcsv(filename)
    cve_desc = {}
    for i in range(11, len(lines)):
        id = lines[i][0]
        if int(id[4:8]) < 2010:
            continue
        cve_desc[id] = lines[i][2].lower()
    return cve_desc

def read_vendor_product(filename):
    lines = open(filename).readlines()
    pid = 0
    product_table = {}
    vendor_dev = {}
    for line in lines:
        line = line.lower().replace("-", '').replace("\"", '')
        line = line.strip('\r\n').split(",")
        if line[0] not in vendor_dev.keys():
            vendor_dev[line[0]] = {line[1]:pid}
        else:
            vendor_dev[line[0]][line[1]]=pid
        product_table[pid] = {"vendor": line[0], "pname": line[1]}
        pid += 1
    return pid, product_table, vendor_dev


def read_vendor_list(file):
    data = []
    lines = open(file).readlines()
    for line in lines:
        line = line.strip('\r\n').lower().replace('\"','').replace('.','')
        if ',' in line:
            line = line.split(',')
            data.extend(line)
        else:
            data.append(line)
    data = list(set(data))
    del data[0]
    return list(set(data))


def read_ent(file):
    with open(file, 'r') as f:
        lines = csv.reader(f)
        ind= {}
        for i,line in enumerate(lines):
            ent = line[0].strip('\r\n')
            ind[ent] = i
    return ind

def read_entvec(file):
    with open(file, 'r') as f:
        data = []
        lines = list(csv.reader(f,delimiter="\t"))
        for line in lines:
            line = [float(x) for x in line]
            data.append(line)
        return np.array(data)