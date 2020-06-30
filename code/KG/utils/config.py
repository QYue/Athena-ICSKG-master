import rdflib
from rdflib import URIRef, BNode, Literal
from utils.readData import *
from utils.check import *
from utils.split_sent import *
from utils.writeFile import *
from utils.model import *
import random
from utils.atomize import *

class Vulnerability:
    def __init__(self, title='', cve='',  intrusion = '', researcher = '',vendor = ''):
        self.title, self.cve,self.intrusion, self.researcher, self.vendor = title, cve, intrusion, researcher, vendor
        self.type = []
        self.vnames = []
        #self.pids = []
        self.CWEs = []
        self.CVSS = {"v2":[],"v3":[]}
        self.infection = {} # {"pid_x":{"affv":"", "credit":1} }
        self.base31, self.temp31 = '',''
        self.av, self.ac, self.ui, self.rc, self.rl = [], [], [], [], []
        self.title = ''
        self.cert_link, self.st_link, self.sf_link, self.nvd_link  = [], [], [], ''
        self.credit = {"av": 1, "vtype": 1, "cvss_score": {"cert":1, "nvd2":1, 'nvd3':1}, "cvss_vector":{"v2":1, "v3":1}} # cvss_score =0 if and only if unmatches vector.


class KnowledgeGraph:
    def __init__(self, plain=0, json=1, rdf=0, demo=0, root_dir = '../../', check_cwe = 1, read_ics= 1):
        # Path
        self.ROOT_DIR = root_dir
        self.DATA_DIR = os.path.join(self.ROOT_DIR, 'data/')
        self.RESULT_DIR = os.path.join(self.ROOT_DIR, 'result/')

        # format of output
        self.PLAIN = plain
        self.JSON = json
        self.RDF = rdf
        self.DEMO = demo

        self.FC_SAMPLE = 20


        # external pre-knowledge from official website: CWE, CVE, CPE
        self.VTypes,self.CWEdict = read_cwe_list(os.path.join(self.DATA_DIR+'CWE/cwe_type.csv')) # VTypes is a list of vulnerability type, CWE dict use vtype as key and CWE-ID as value

        self.CVEdesc = read_ics_cve(os.path.join(self.DATA_DIR+'CVE/ics_cve.csv'))
        self.allCVEs=read_cve_desc(os.path.join(self.DATA_DIR+'CVE/allitems.csv'))
        self.Vendors = read_vendor_list(os.path.join(self.DATA_DIR+'vendor.csv'))
        self.CHECK_CWE = check_cwe
        self.s1, self.s2, self.s3 = cwe_tree(), cwe_tree(), cwe_tree()


        # entity identifier
        self.vul_id, self.inf_id, self.p_id = 0, 0, 0
        self.vtype_id, cvss_id = 0, 0
        self.av_id, self.ac_id, self.ui_id, self.rc_id, self.rl_id = 0, 0, 0, 0, 0

        # domain in rdf
        self.vul_prex = 'http://example.org/vulnerability/'
        self.vtype_prex = 'http://example.org/vulType/'
        self.cvss_prex = 'http://example.org/CVSS/'
        self.av_prex = 'http://example.org/AttackVector/'
        self.ac_prex = 'http://example.org/AttackComplexity/'
        self.ui_prex = 'http://example.org/UserInteraction/'
        self.rc_prex = 'http://example.org/ReportConfidence/'
        self.rl_prex = 'http://example.org/RemediationLevel/'

        # KG in different format
        self.rdfKG = rdflib.Graph()
        self.jsonKG = {'Vulnerabilities':[]}
        self.demoKG = {'Vulnerabilities':[]}
        self.plainKG = []

        # entity tables (main content of the KG) and identity tables (helps identify entities)
        self.vul_table = {} # records of vulnerability entity
        self.vtype_vul = {}  # key:vtype, value: a list of vul_id with the vtype "vtype":[{"id":"", "ap":[],"intrusion":""}]
        self.cve_table = {}  # key: cve-id, value: the vul_id with the cve-id
        self.product_table = {} # records of product entity
        self.vendor_dev = {} # {"vendor1":{"pname1":"p_id1", ...,}}= {}
        self.unie = {}

        # source record tables
        self.sf_table = {} # key: cve-id, with vulnerability info extracted from securityFocus
        self.st_table = {}  # key: cve-id, with vulnerability info extracted from securityTracker
        self.nvd_table = {} # key: cve-id, with vulnerability info extracted from NVD
        self.cert_table = [] # a list for CERT records

        if read_ics:
            self.p_id, self.product_table, self.vendor_dev = read_vendor_product(os.path.join(self.DATA_DIR,
                                                                                              'ics_products.csv'))

        self.inconsistency = {
                              "vector-score":{"v2":{"cert":0,"nvd":0},"v3":{"cert":0,"nvd":0}},
                              "vector-text":{"av":0,"ac":0,"ui":0},

                                "avtext": {"num": 0, "vulList": [], "detail": []},  # detail: {"cve":"","cert":"","sf":""}
                                "vector": {"v2":{"num": 0, "vulList": [], "detail": []},"v3":{"num": 0, "vulList": [], "detail": []}},  # deta8il: {"cve": "", "cert": "", "nvd": ""}
                                "vultype": {"unmatched": 0, "conflict": 0},
                                "affected version": {"sf": 0, "st": 0, "nvd": 0},
                            }

    def build_cwe_tree(self):
        by_research = 'https://cwe.mitre.org/data/definitions/1000.html'
        by_develop = 'https://cwe.mitre.org/data/definitions/699.html'
        by_architecture = 'https://cwe.mitre.org/data/definitions/1008.html'
        print('Start building cwe tree')
        self.s1.get_cwe_tree(by_research, '1000284', 'research_tree')
        self.s2.get_cwe_tree(by_develop, '6991228', 'develop_tree')
        self.s3.get_cwe_tree(by_architecture, '10081009', 'architecture_tree')
        print('finished')


    def get_vul_id(self,vul, AP):
        vtype = vul["Type"].lower()
        if ' cwe' in vtype:
            vtype = vtype[:vtype.index(" cwe")]
        #cwe = vul["CWE"]
        cve = vul["CVE"].lower()
        #cvss = vul["CVSS"]
        intrusion = vul["Intrusion"].lower()
        vul_id = -1
        if cve:
            if cve in self.cve_table.keys():
                vul_id = self.cve_table[cve]
            else:
                vul_id = self.vul_id
                self.vul_id += 1
                self.cve_table[cve] = vul_id
        if vtype:
            match_p, match_in = 0, 0
            if vtype in self.vtype_vul.keys():
                vcans = self.vtype_vul[vtype]
                for v in vcans:
                    for rp in v['ap']:
                        for ap in AP:
                            pname = ap['Pname'].lower()
                            if rp == pname:
                                match_p = 1
                                break
                        break
                    if match_p:
                        if not intrusion or match_intrusion(intrusion, v["intrusion"]):
                            match_in = 1
                            if not vul_id:
                                vul_id = v["id"]
                            break
                if not (match_p and match_in):
                    if not vul_id:
                        vul_id = self.vul_id
                        self.vul_id += 1
                    ap = []
                    for item in AP:
                        ap.append(item["Pname"])
                    self.vtype_vul[vtype].append({"id": vul_id, "ap": ap, "intrusion": intrusion})
            else:
                if not vul_id:
                    vul_id = self.vul_id
                    self.vul_id += 1
                ap = []
                for item in AP:
                    ap.append(item["Pname"])
                self.vtype_vul[vtype] = [{"id": vul_id, "ap": ap, "intrusion": intrusion}]
        return vul_id, cve, vtype, intrusion

    def get_product_id(self,pname,vendor):

        if vendor and vendor in pname:
            pname, vendor = split_vendor_device(pname, vendor, self.Vendors)
        '''identify product entity, if the product is new, assign a new id and add product info to product_table and vendor_dev'''

        if vendor in self.vendor_dev.keys():
            if pname in self.vendor_dev[vendor].keys():
                p_id = self.vendor_dev[vendor][pname]
            elif pname.replace(' ','') in self.vendor_dev[vendor].keys():
                p_id = self.vendor_dev[vendor][pname.replace(' ','')]
            else:
                p_id = self.p_id
                self.p_id += 1
                self.vendor_dev[vendor][pname] = p_id
                self.product_table[p_id]={"pname":pname,"vendor":vendor}
        else:
            p_id = self.p_id
            self.p_id += 1
            self.vendor_dev[vendor] = {pname:p_id}
            self.product_table[p_id] = {"pname": pname, "vendor": vendor}

        return p_id

    def add_cert_info(self,cert_path):
        self.cert_table = read_cert_table(cert_path)
        for record in self.cert_table:
            title = record["Title"]
            link = record["Link"]
            researcher = record["Researcher"]
            vendor = record["Vendor"].lower()

            AP = record["Affected Products"] # a list
            for ap in AP:
                p_id = self.get_product_id(ap["Pname"].lower(),vendor)
                ap["pid"]=p_id

            av, ac, ui = read_cert_mv(record, link)#record["AV"], record["AC"], record["UI"]
            #av["source"], ac["source"], ui["source"] = link, link, link\
            for vulitem in record["Vulnerabilities"]:
                '''get vulnerability id'''
                vul_id, cve, vtype, intrusion = self.get_vul_id(vulitem,AP)

                # if the vulnerability is new
                if vul_id not in self.vul_table.keys():

                    vul = Vulnerability(title,cve, intrusion, researcher,vendor)
                    vul.type = [{"CWE-ID":vulitem["CWE"], "Vulnerability Type": vtype, "source":link}]

                    if vtype not in self.VTypes:
                        self.VTypes.append(vtype)
                    if vtype not in vul.vnames:
                        vul.vnames.append(vtype)
                    vul.CWEs.append(vulitem["CWE"].lower())
                    # add CVSS
                    cvss = vulitem["CVSS"]
                    if '2' in cvss["version"]:
                        cvss["version"] =  'v2'
                    if '3' in cvss["version"]:
                        cvss["version"] = 'v3'
                    # check if the cvss vector unmatch the score
                    if conflict_vector_score(cvss):
                        self.inconsistency["vector-score"][cvss["version"]]["cert"]+=1
                        vul.credit["cvss_score"]['cert']=0
                    # check if the cvss vector unmatch the text evidence
                    av_conflict, ac_conflict, ui_conflict = conflict_metric_value(vul,cvss,av, ac, ui)
                    self.inconsistency["vector-text"]["av"] += av_conflict
                    self.inconsistency["vector-text"]["ac"] += ac_conflict
                    self.inconsistency["vector-text"]["ui"] += ui_conflict

                    cvss['source'] = link
                    vul.CVSS[cvss["version"]] = [cvss]

                    for ap in AP:
                        vul.infection[ap["pid"]]={'affv': ap["version"], 'credit': 1}
                        #vul.infection.append({"product":ap["pid"],"affected version":ap["version"],'credit':1})
                        #vul.pids.append(ap["pid"])

                    vul.av, vul.ac, vul.ui = [av], [ac], [ui]
                    self.vul_table[vul_id] = vul
                else:
                    vul = self.vul_table[vul_id]
                    cwe =  vulitem["CWE"].lower()
                    if cwe not in vul.CWEs or vtype not in vul.vnames:
                        vul.type.append({"CWE-ID":cwe, "Vulnerability Type": vtype, "source":link})
                        vul.CWEs.append(cwe)
                        vul.vnames.append(vtype)
                        self.inconsistency["vultype"]["unmatched"] += 1
                        if self.CHECK_CWE:
                            for bcwe in vul.CWEs:
                                if conflict_vtype(bcwe, cwe,[self.s1, self.s2, self.s3]):
                                    self.inconsistency["vultype"]["conflict"] += 1
                                    vul.credit["vtype"] = 0
                '''insert vulnerability into vul_table'''
                self.vul_table[vul_id] = vul
                # vul_id = self.vul_id
                # self.vul_id += 1
                #

    def merge_sf(self):
        for cve in self.sf_table.keys():
            sf_vul = self.sf_table[cve]
            sf_link = "https://www.securityfocus.com/bid/" + sf_vul['id']
            # identify the vulnerability: first use cve-id, if not matched then check vtype, intusion and affected device
            if cve in self.cve_table.keys():
                v_id = self.cve_table[cve]
            else:
                #print("CVE in SF not in cert:",cve)
                continue
                # v_id = self.vul_id
                # self.vul_id += 1
                # self.vul_table[v_id] = Vulnerability()
            vul = self.vul_table[v_id]
            # add cvss metric value text evidence
            if sf_vul['av'] and vul.av[0]["value"]:
                # check inconsistency in cvss metric value text evidence
                if sf_vul["av"]!= vul.av[0]["value"]:
                    vul.credit['av'] = 0
                    self.inconsistency["avtext"]["num"]+=1
                    self.inconsistency["avtext"]["vulList"].append(v_id)
                    self.inconsistency["avtext"]["detail"].append({"cve":cve,"cert":vul.av[0]["text"],"sf":sf_vul["avtext"]})
                # add new av text evidence
                vul.av.append({"text": sf_vul["avtext"], "value":sf_vul["av"], "source":sf_link})
            if sf_vul['type'] not in self.VTypes:
                self.VTypes.append(sf_vul['type'])
            # add affected product (extract vendor name from sf_vul['device])
            if sf_vul['device']:
                sf_product, sf_vendor = split_vendor_device(sf_vul['device'], vul.vendor, self.Vendors)

                if sf_product:
                    sf_pid = self.get_product_id(sf_product, sf_vendor)
                    if sf_pid  in vul.infection.keys():
                        ver_ = vul.infection[sf_pid]

                        if not match_version(ver_, sf_vul["affv"]):
                            vul.infection[sf_pid]["credit"] = 0
                            self.inconsistency["affected version"]["sf"] += 1
                    else:
                        vul.infection[sf_pid]={"affv": sf_vul['affv'], 'fix': sf_vul["fix"], 'credit':1}


    def merge_st(self):
        for cve in self.st_table.keys():
            st_vul = self.st_table[cve]
            st_link = "https://securitytracker.com/id/" + st_vul['id']
            # identify the vulnerability: first use cve-id, if not matched then check vtype, intusion and affected device
            if cve in self.cve_table.keys():
                v_id = self.cve_table[cve]
            else:
                #print("CVE in ST not in cert:", cve)
                continue
            vul = self.vul_table[v_id]
            # add cvss metric value text evidence
            if st_vul['rc']:
                vul.rc.append({"text": st_vul["rctext"], "value":st_vul["rc"], "source":st_link})
            if st_vul['rl']:
                vul.rl.append({"text": st_vul["rctext"], "value":st_vul["rl"], "source":st_link})
            # add affected product
            if st_vul['vendor'] and st_vul['product']:
                st_vendor, st_product =  st_vul['vendor'].lower(), st_vul['product'].lower()

                # check inconsistency in affected version
                if st_product:
                    st_pid = self.get_product_id(st_product, st_vendor)

                    if st_pid in vul.infection.keys():

                        ver_ = vul.infection[st_pid]
                        if not match_version(ver_, st_vul["version"]):
                            vul.infection[st_pid]["credit"] = 0
                            self.inconsistency["affected version"]["st"] += 1
                    else:
                        vul.infection[st_pid]={"affv": st_vul['version'], 'fix': st_vul["fix"], 'credit': 1}


    def merge_nvd(self):
        for cve in self.nvd_table.keys():
            nvd_vul = self.nvd_table[cve]
            if cve in self.cve_table.keys():
                v_id = self.cve_table[cve]
            else:
                continue
            vul = self.vul_table[v_id]
            # cvss
            nvd_link = "https://nvd.nist.gov/vuln/detail/" + cve.upper()

            for cvss in vul.CVSS["v3"]:
                if cvss["vector"]and nvd_vul["cvss_3_vector"] and cvss["vector"].lower() !=nvd_vul["cvss_3_vector"] :
                    self.inconsistency["vector"]["v3"]["num"] += 1
                    self.inconsistency["vector"]["v3"]["vulList"].append(v_id)
                    self.inconsistency["vector"]["v3"]["detail"].append(
                        {'cve': cve, "cert": cvss["vector"], "nvd": nvd_vul["cvss_3_vector"]})
            for cvss in vul.CVSS["v2"]:
                if cvss["vector"] and nvd_vul["cvss_2_vector"] and cvss["vector"].lower() != nvd_vul["cvss_2_vector"]:
                    self.inconsistency["vector"]["v2"]["num"] += 1
                    self.inconsistency["vector"]["v2"]["vulList"].append(v_id)
                    self.inconsistency["vector"]["v2"]["detail"].append(
                        {'cve': cve, "cert": cvss["vector"], "nvd": nvd_vul["cvss_2_vector"]})


            if nvd_vul["cvss_3_vector"] and nvd_vul["cvss_3_score"]:
                cvss = {"vector": nvd_vul["cvss_3_vector"] ,"version":"v3","base score": nvd_vul["cvss_3_score"],"source": nvd_link}
                if conflict_vector_score(cvss):
                    self.inconsistency["vector-score"][cvss["version"]]["nvd"] += 1
                    vul.credit["cvss_score"]['nvd3'] = 0
                vul.CVSS["v3"].append(cvss)

            if nvd_vul["cvss_2_vector"] and nvd_vul["cvss_2_score"]:
                cvss = {"vector": nvd_vul["cvss_2_vector"], "version": "v2", "base score": nvd_vul["cvss_2_score"],
                        "source": nvd_link}
                if conflict_vector_score(cvss):
                    self.inconsistency["vector-score"][cvss["version"]]["nvd"] += 1
                    vul.credit["cvss_score"]['nvd2'] = 0
                vul.CVSS["v2"].append(cvss)
            # vtype
            for vtype in nvd_vul['type']:
                if vtype not in self.VTypes:
                    self.VTypes.append(vtype)
            for cwe in nvd_vul['cwe']:
                if cwe and cwe not in vul.CWEs:
                    self.inconsistency["vultype"]["unmatched"] += 1
                    if self.CHECK_CWE:
                        for bcwe in vul.CWEs:
                            if conflict_vtype(bcwe, cwe, [self.s1, self.s2, self.s3]):
                                self.inconsistency["vultype"]["conflict"] += 1
                                vul.credit["vtype"] = 0
                    vul.CWEs.append(cwe)
            # affected product
            for p in nvd_vul['ap'].keys():
                nvd_version = ",".join(nvd_vul['ap'][p])

                nvd_pname,nvd_vendor  =split_vendor_device(p, vul.vendor, self.Vendors)

                if nvd_pname:
                    nvd_pid = self.get_product_id(p, nvd_vendor)
                    if nvd_pid in vul.infection.keys():
                        ver_ = vul.infection[nvd_pid]
                        if not match_version(ver_, nvd_version):
                            vul.infection[nvd_pid]["affv"] = nvd_version
                            vul.infection[nvd_pid]["credit"] = 0
                            self.inconsistency["affected version"]["nvd"] += 1
                    else:
                        vul.infection[nvd_pid]={"affv": nvd_version, 'credit': 1}


    def extendKG(self, st_path, sf_path, nvd_path):
        self.sf_table, self.st_table = read_thirdparty_vuls(st_path, sf_path)
        self.nvd_table = read_nvd_vuls(nvd_path)
        #print(self.nvd_table.keys())
        print("Add SecurityFocus reports to KG:")

        self.merge_sf()
        print("Finished")
        print("Add SecurityTracker reports to KG:")
        self.merge_st()
        print("Finished")
        print("Add NVD reports to KG:")
        self.merge_nvd()
        print("Finished")


    def buildKG(self, cert_dir, st_dir, sf_dir, nvd_dir):
        cert_path = os.path.join(self.RESULT_DIR, cert_dir)
        sf_path, st_path, nvd_path = os.path.join(self.DATA_DIR, sf_dir), os.path.join(self.DATA_DIR, st_dir), os.path.join(self.DATA_DIR, nvd_dir)
        if self.CHECK_CWE:
            self.build_cwe_tree()
        print("Add CERT reports to KG:")
        self.add_cert_info(cert_path)
        self.extendKG( st_path, sf_path, nvd_path)


    def evaluate_fact_checking(self):
        cves = [x for x in self.st_table.keys() if x in self.sf_table.keys()]
        sample_cves = random.sample(cves,self.FC_SAMPLE)
        vul_table = []
        for  cve in sample_cves:
            vul_id = self.cve_table[cve]
            vul = self.vul_table[vul_id]
            vul_table.append(vul)
        # TODO
        #write_fc(vul_table, os.path.join(self.RESULT_DIR, 'evaluation/factChecking.csv'))


    def report_inconsistency(self):
        with open(os.path.join(self.RESULT_DIR, "inconsistency.json"), 'w') as f:
            json.dump(self.inconsistency, f, indent=4)

    def extendCorpus(self,num):
        allcves = self.allCVEs.keys()
        ics_cves = self.CVEdesc.keys()
        ex_cves = [x for x in allcves if x not in ics_cves]
        add_cves = random.sample(ex_cves,num)
        for cve in add_cves:
            self.CVEdesc[cve] = self.allCVEs[cve]

    def makeCorpus(self):
        evaluate_cves = []
        corpus = []
        subs = []
        unie = {}
        with open(os.path.join(self.RESULT_DIR, "GroundTruth/cve_gt.json"), 'r') as f:
            gt = json.load(f)
            for item in gt['CVE Data']:
                evaluate_cves.append(item['CVE'])
                sub_sents = replace_entities_in_sentence(item)
                subs.extend(sub_sents)
        #self.extendCorpus(1000)
        for cve in self.CVEdesc.keys():
            sent = self.CVEdesc[cve]
            entry = {'vtype': '', 'vendor': '', 'intrusion': '', 'ap': []}
            vtype_dict, vendor_dict = self.VTypes, self.Vendors
            pnames = []
            if cve in self.cve_table:
                vul_id = self.cve_table[cve]
                vul = self.vul_table[vul_id]
                vtype_dict = vul.vnames + self.VTypes
                vendor_dict = vul.vendor + self.Vendors
                for pid in vul.infection.keys():
                    pnames.append(self.product_table[pid]["pname"])
            sent, entry = combine_chunk(sent, entry, vtype_dict, vendor_dict,pnames)
            if cve in evaluate_cves:
                unie[cve] = {"Description":self.CVEdesc[cve],"Tokenized Sentence":sent,"Entities":entry}
            corpus.append(sent)
        corpus.extend(subs)
        self.unie = unie
        write_corpus(corpus, self.RESULT_DIR+"embedding/corpus.txt",self.DATA_DIR+"CERT/Advisories", self.CVEdesc.values())

        with open(os.path.join(self.RESULT_DIR,'IE/ics_cve.json'),'w') as f:
            json.dump(unie, f, indent=4)

    def unstructredIE(self,corpus_dir,model_dir):
        corpus_path = os.path.join(self.RESULT_DIR,corpus_dir)
        model_path = os.path.join(self.RESULT_DIR,model_dir)
        if not  os.path.exists(corpus_path):
            self.makeCorpus()
        model = get_emb_model(corpus_path, model_path)
        align,p_kge_vec, v_kge_vec = train_align_matrix(model)
        for id in self.unie.keys():
            item = self.unie[id]
            self.unie[id]['Entities']['ap'].extend( extract_ap(item, align,model,p_kge_vec, v_kge_vec))
