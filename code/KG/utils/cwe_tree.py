# -*- coding: utf-8 -*-‘
import os
import re
import csv
import treelib
from urllib import request
from bs4 import BeautifulSoup
import requests
from urllib.request import urlopen
from treelib import Node,Tree


# tree = {}
# name = {'https://cwe.mitre.org/data/definitions/1000.html':'research_tree','https://cwe.mitre.org/data/definitions/699.html':'develop_tree','https://cwe.mitre.org/data/definitions/1008.html':'architecture_tree'}
# spec = {'https://cwe.mitre.org/data/definitions/1000.html':'1000682','https://cwe.mitre.org/data/definitions/699.html':'69916','https://cwe.mitre.org/data/definitions/1008.html':'10081009'}
# for url in ['https://cwe.mitre.org/data/definitions/1000.html','https://cwe.mitre.org/data/definitions/699.html','https://cwe.mitre.org/data/definitions/1008.html']:
class cwe_tree():
    def __init__(self):
        super(cwe_tree, self).__init__()
        self.u = 0
        self.dic = []
        self.count = 0
        self.cwe_dic = {}
        self.report_dic = []
        self.cwe_dic2 = {}
        self.tree = Tree()
        self.case = 0
        self.match_case = 0
        self.othertype = 0
        self.insufficient = 0
        self.bias_case = 0
        self.lost_case = 0
        self.bias_year = [0,0,0,0,0,0,0,0,0,0]
        self.lost_year = [0,0,0,0,0,0,0,0,0,0]
        
    def grab(self,sid,node):
        # global u
        # global dic
        # global count
        try:
            mysid = node.attrs['id']
            try:
                cwe_name = node.find('span',class_='graph_title',recursive = False).find('span',class_ = 'Primary',recursive = False).find('a').get_text()
            except:
                cwe_name = node.find('span',class_ = 'Secondary').find('a').get_text() 
            summary = node.find('div',class_ = 'defsummary').get_text()   
            self.dic.append({'cwe_name':cwe_name,'mysid':mysid,'id':self.count,'summary':summary,'parent':sid})
            self.cwe_dic[mysid] ={'cwe_name':cwe_name,'mysid':mysid,'id':self.count,'summary':summary,'parent':sid}
            #TODO
            self.count += 1        
            try:
                children = node.find('div',class_ = 'collapseblock')
                for child in children.find_all('div',class_ = 'group',recursive=False):                
                    self.grab(mysid,child)
            except:
                pass
        except:
            self.u += 1
            if node:
                print(node.attrs['id'])
            pass

    def init_tree(self,name):
        self.dic_name = name

    def get_cwe_tree(self,url,spec,name):
        head = {}
        # url="https://cwe.mitre.org/data/definitions/699.html"
        head['User-Agent'] = 'Mozilla/5.0 (Linux; Android 4.1.1; Nexus 7 Build/JRO03D) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166  Safari/535.19'
        response = urlopen(url)
        html = response.read()
        soup = BeautifulSoup(html, 'html.parser')
        self.dic_name = name
        
        # node = soup.find('div',class_ = 'group',id = spec[url])
        node = soup.find('div',class_ = 'group',id = spec)
        self.grab('0',node)
        for jar in node.next_siblings:
            if jar.attrs['class'] == ['group']:
                self.grab('0',jar)
        
        
        headers = ['cwe_name','id','mysid','summary','parent']
        # file = './results/'+name[url]
        file = '../../result/ER/'+name
        filename = file+'.csv'
        if os.path.exists(filename):
            os.remove(filename)
        with open(filename,'w') as f:
            f_csv = csv.DictWriter(f, headers)
            f_csv.writerows(self.dic)
        # print('error:',self.u)
        
        self.tree.create_node('Root','root')
        for i in self.cwe_dic.keys():
            node = self.cwe_dic[i]
            parent = node['parent']
            try:
                if parent == '0':
                    self.tree.create_node(node['cwe_name'],node['mysid'],parent = 'root',data = node)
                else:
                    self.tree.create_node(node['cwe_name'],node['mysid'],parent = parent,data = node)
            except:
                print('error: ',node['id'])
                pass
        if os.path.exists(file):
            os.remove(file)
        self.tree.save2file(file, nid=None, level=0, idhidden=True, filter=None, key=None, reverse=False, line_type=u'ascii-ex', data_property=None)
      
    def Max(self,a,b):
        return (len(a) if len(a)>len(b) else len(b))

    def get_result(self,path):
        for file in os.listdir(path):
            filename = path+file
            with open(filename,'r') as f:
                while True:
                    row = f.readline()
                    if not row:
                        break
                    if '>>>vulnerability' in row:
                        vul_list = []
                        while True:
                            row = f.readline()
                            if '>>>researcher' in row:
                                print('MISSING ENDING STRING VULNERABILITY')
                                print('FILE NAME: '+filename+'\n')
                                break
                            if '<<<vulnerability' in row:
                                break
                            vul_list.append(row.strip())
                        self.match_eval(vul_list,filename)
        print('totle case number:',self.case)
        print('totle match case: ',self.match_case)
        print('totle bias case: ', self.bias_case)
        print('totle lost case: ', self.lost_case)

    def assess(self, vul, name):
        sid = []
        for i in self.cwe_dic.keys():
            if Levenshtein(self.cwe_dic[i]['cwe_name'], vul.replace('CWE-', '')) < 5:
                sid.append(i)
        if sid == []:
            print('fail to match record: ', vul.replace('CWE-', ''))
        pos = set()
        for i in sid:
            for j in self.cwe_dic.keys():
                if self.tree.is_ancestor(i, j):
                    pos.add(self.cwe_dic[j]['cwe_name'])
                if self.tree.is_ancestor(j, i):
                    pos.add(self.cwe_dic[j]['cwe_name'])
                for k in self.tree.siblings(j):
                    #                 print(k)
                    pos.add(k.data['cwe_name'])
        for i in pos:
            if Levenshtein(i.replace('(', '').replace(')', '').lower(), name.replace('CWE-', '').replace('(', '').replace(')', '').lower()) < 6:
                return True
            name1 = name.split('CWE')[0].replace('(', '').replace(')', '').replace(' ', '').lower()
            i1 = i.split('-')[0].replace('(', '').replace(')','').replace(' ', '').lower()
            if name1 in i1:
                return True
            if i1 in name1:
                return True
            Len = self.Max(name1, i1)
            if Levenshtein(name1, i1) < int(0.25*Len):
                return True
            try:
                i2 = i.split('-')[1].replace(')','').replace('(', '').replace(' ', '')
                name2 = name.split('CWE')[1].replace('(', '').replace(')', '').replace('-', '').replace(' ', '')
                if i2 == name2:
                    return True
            except:
                pass
        return False

    def match_eval(self,par,filename):

        name = par[1].replace('name:','').strip()
        cve_number = par[3].replace('CVE number:', '').replace(
            'CVE NUMBER:', '').replace('cve number:', '').strip().upper()

        url = 'https://nvd.nist.gov/vuln/detail/'+cve_number
        head = {}
        head['User-Agent'] = 'Mozilla/5.0 (Linux; Android 4.1.1; Nexus 7 Build/JRO03D) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166  Safari/535.19'


        try:
            req = request.Request(url, headers=head)
            response = request.urlopen(req)
            html = response.read()
            soup = BeautifulSoup(html, 'html.parser')
            try:
                vul = soup.find('li',attrs={'data-testid':'vuln-technical-details-0-link'}).get_text()
    #             print(vul,'\n')
            except:
                print('the cve_report has been rejected: ',filename)
                vul = 'Rejected'
                # self.case+=1
                # self.lost_case+=1

            if vul != 'Rejected':
                if vul == 'Other (NVDold-CWE-Other)':
                    self.case += 1
                    self.othertype += 1
                    self.report_dic.append({'cve_number':cve_number,'status':'othertype','vul_in_advisory':name,'vul_in_cve':vul,'filename':filename}) 
                    return 0
                if vul == 'Insufficient Information (NVDold-CWE-noinfo)':
                    self.case += 1
                    self.insufficient += 1
                    self.report_dic.append({'cve_number': cve_number, 'status': 'insufficient','vul_in_advisory': name, 'vul_in_cve': vul, 'filename': filename})
                    return 0
                if Levenshtein(vul.lower(),name.lower())<6:
                    self.case+=1
                    self.match_case+=1
                    self.report_dic.append({'cve_number':cve_number,'status':'match','vul_in_advisory':name,'vul_in_cve':vul,'filename':filename})
    #                 print('positive for vulnerability: ',name,'\n','file: ',filename)
                    return 0
                else:
                    if self.assess(vul,name):
                        self.case+=1
                        self.match_case+=1
                        self.report_dic.append({'cve_number':cve_number,'status':'match','vul_in_advisory':name,'vul_in_cve':vul,'filename':filename})
                        return 0
                    else:
                        print('bias',cve_number,filename)
                        print(vul)
                        print(name,'\n')
                        self.case+=1
                        self.bias_year[int(filename.split('-')[1])-10]+=1
                        self.bias_case+=1
                        self.report_dic.append({'cve_number':cve_number,'status':'bias','vul_in_advisory':name,'vul_in_cve':vul,'filename':filename})
                        return 0
    #                 print('negative for vulnerability: ',name,'\n','file: ',filename) 
            else:
                print('5')
                self.case += 1
                self.lost_year[int(filename.split('-')[1])-10]+=1
                self.lost_case +=1 
                self.report_dic.append({'cve_number':cve_number,'status':'reject','vul_in_advisory':name,'vul_in_cve':vul,'filename':filename})
                print(cve_number, ' has been rejected',filename,'\n')
                return 0
                
        except:
            print('url error')
            self.case+=1
            self.lost_year[int(filename.split('-')[1])-10]+=1
            self.lost_case+=1
            self.report_dic.append({'cve_number':cve_number,'status':'url error','vul_in_advisory':name,'vul_in_cve':'','filename':filename})

    def cve_eval(self,path,storepath):
        for file in os.listdir(path):
            filename = path+file
        # filename = '/content/drive/My Drive/ICS KnowledgeGraph/ICSA_report/advisory_data/info_gt_ICS Advisory (ICSA-19-010-02).txt'
            with open(filename,'r') as f:
                while True:
                    row = f.readline()
                    if not row:
                        break
                    if '>>>vulnerability' in row:
                        vul_list = []
                        while True:
                            row = f.readline()
                            if '>>>researcher' in row:
                                print('MISSING ENDING STRING VULNERABILITY')
                                print('FILE NAME: '+filename+'\n')
                                break
                            if '<<<vulnerability' in row:
                                break
                            vul_list.append(row.strip())
                        self.match_eval(vul_list,filename)
        print('totle case number:',self.case)
        print('totle match case: ',self.match_case)
        print('totle bias case: ', self.bias_case)
        print('totle lost case: ', self.lost_case)
        print('totle othertype case: ', self.othertype)
        print('totle insufficient case: ', self.insufficient)
        print('bias year:')
        print(self.bias_year)
        print(self.lost_year)
        for i in range(10):
            print('bias year 20',str(i+10),':',self.bias_year[i])
        for i in range(10):
            print('lost year 20',str(i+10),':',self.lost_year[i])
        headers = ['cve_number','status','vul_in_advisory','vul_in_cve','filename']
        with open(storepath,'w') as w:
            f_csv = csv.DictWriter(w, headers)
            f_csv.writerows(self.report_dic)
            


    #return if id1 and id2 are relatives
    def is_cwe_affiliate(self,id1,id2):
        #get the cwe number  
        cwe1 = '('+id1.lower().replace('cwe','').replace('-','')+')'
        cwe2 = '('+id2.lower().replace('cwe','').replace('-','')+')'
        file = '../../result/ER/'+self.dic_name+'.csv'
        tmp_dic = [] #store cwe nodes with same cwe_name 
        cwe1_list = [] #store all cwe contains the same cwe id1
        cwe2_list = [] #store all cwe contains the same cwe id2

        #get tag and identifier of records in cwe tree stored in csv file
        with open(file,'r') as f:
            f_csv = csv.reader(f)
            for row in f_csv:
                tmp_dic.append([row[0],row[2]]) #row[0] is record name(tag), row[1] is record identifier(nid)
        for i in tmp_dic:
            if cwe1 in i[0]:
                cwe1_list.append(i) #all cwe records with the same id id1
            if cwe2 in i[0]:
                cwe2_list.append(i) #all cwe records with the same id id2
        if cwe1_list == []: #no records found for id1
            #print('id1 not found')
            return False
        if cwe2_list == []: #no records found for id2
           # print('id2 not found')
            return False

        # print('\nPossible cwe1:') #print out all records with cwe_id of id1
        # for i in cwe1_list:
        #     print(self.tree.get_node(i[1]).tag)
        # print('\nPossible cwe2:') #print out all records with cwe_id of id2
        # for i in cwe2_list:
        #     print(self.tree.get_node(i[1]).tag)
        # print()

        #clarify relationship
        for i in cwe1_list: #loop in every records in cwe1_list, if match, stop and return
            for j in cwe2_list: #loop in every records in cwe2_list, if match, stop and return
                if self.tree.is_ancestor(i[1],j[1]): #id1 is ancestor of id2
                    #print('id1 is ancestor of id2')
                    return True,self.tree.get_node(i[1]).tag
                if self.tree.is_ancestor(j[1],i[1]): #id2 is ancestor of id1
                    #print('id2 is ancestor of id1')
                    return True,self.tree.get_node(j[1]).tag
                if j[0] in self.tree.siblings(i[1]): #id1 and id2 are siblings
                   # print('id1 and id2 are siblings\nancestor is: \n'+self.tree.parent(j[1]).tag)#return the nearest parent
                    return True,self.tree.parent(j[1]).tag

                #get the nearest ancestor
                cwe1_parents = []
                cwe2_parents = []
                cwe1_parent_node = self.tree.parent(i[1])
                cwe2_parent_node = self.tree.parent(j[1])
                while cwe1_parent_node.is_root()==False:
                    cwe1_parents.append(cwe1_parent_node)
                    cwe1_parent_node = self.tree.parent(cwe1_parent_node.identifier)
                while cwe2_parent_node.is_root()==False:
                    cwe2_parents.append(cwe2_parent_node)
                    cwe2_parent_node = self.tree.parent(cwe2_parent_node.identifier)
                for m in cwe1_parents:
                    for n in cwe2_parents:
                        if m == n:
                           # print('id1 and id2 are relatives')
                           # print('ancestor is: ',end = '')
                           # print(m.tag)
                            return True,m.tag

        return False
#return if id1 and id2 are relatives
    def is_name_affiliate(self, id1, id2):
        #get the cwe number
        cwe1 = id1.lower().split('cwe')[0].strip()
        cwe2 = id2.lower().split('cwe')[0].strip()

        file = '../../result/ER/'+self.dic_name+'.csv'
        tmp_dic = []  # store cwe nodes with same cwe_name
        cwe1_list = []  # store all cwe contains the same cwe id1
        cwe2_list = []  # store all cwe contains the same cwe id2

        #get tag and identifier of records in cwe tree stored in csv file
        with open(file, 'r') as f:
            f_csv = csv.reader(f)
            for row in f_csv:
                # row[0] is record name(tag), row[1] is record identifier(nid)
                tmp_dic.append([row[0], row[2]])
        for i in tmp_dic:
            # if cwe1 in i[0]:
            if Levenshtein(cwe1,i[0].lower().split('-')[0].strip())<4:
                cwe1_list.append(i)  # all cwe records with the same id id1
            # if cwe2 in i[0]:
            if Levenshtein(cwe2, i[0].lower().split('-')[0].strip()) < 4:
                cwe2_list.append(i)  # all cwe records with the same id id2
        if cwe1_list == []:  # no records found for id1
            print('id1 not found')
            return False
        if cwe2_list == []:  # no records found for id2
            print('id2 not found')
            return False
        print('\nPossible cwe1:')  # print out all records with cwe_id of id1
        for i in cwe1_list:
            print(self.tree.get_node(i[1]).tag)
        print('\nPossible cwe2:')  # print out all records with cwe_id of id2
        for i in cwe2_list:
            print(self.tree.get_node(i[1]).tag)
        print()

        #clarify relationship
        for i in cwe1_list:  # loop in every records in cwe1_list, if match, stop and return
            for j in cwe2_list:  # loop in every records in cwe2_list, if match, stop and return
                if self.tree.is_ancestor(i[1], j[1]):  # id1 is ancestor of id2
                    print('id1 is ancestor of id2')
                    return True, self.tree.get_node(i[1]).tag
                if self.tree.is_ancestor(j[1], i[1]):  # id2 is ancestor of id1
                    print('id2 is ancestor of id1')
                    return True, self.tree.get_node(j[1]).tag
                # id1 and id2 are siblings
                if j[0] in self.tree.siblings(i[1]):
                    print('id1 and id2 are siblings\nancestor is: \n' +
                          self.tree.parent(j[1]).tag)  # return the nearest parent
                    return True, self.tree.parent(j[1]).tag

                #get the nearest ancestor
                cwe1_parents = []
                cwe2_parents = []
                cwe1_parent_node = self.tree.parent(i[1])
                cwe2_parent_node = self.tree.parent(j[1])
                while cwe1_parent_node.is_root() == False:
                    cwe1_parents.append(cwe1_parent_node)
                    cwe1_parent_node = self.tree.parent(
                        cwe1_parent_node.identifier)
                while cwe2_parent_node.is_root() == False:
                    cwe2_parents.append(cwe2_parent_node)
                    cwe2_parent_node = self.tree.parent(
                        cwe2_parent_node.identifier)
                for m in cwe1_parents:
                    for n in cwe2_parents:
                        if m == n:
                            #print('id1 and id2 are relatives')
                            # print('ancestor is: ', end='')
                            # print(m.tag)
                            return True,m.tag
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
            

    
    
    
    
    
    
    
    
    
    
    
