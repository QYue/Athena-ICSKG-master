import requests
from lxml import etree
import string
import time
import csv
import os

# if has Chinese, apply decode()
def get_urls(site):
    urls = []
    if site == 'securityFocus':
        for i in range(3411):
            n = 30*i
            urls.append("https://www.securityfocus.com/cgi-bin/index.cgi?o="+str(n)+"&l=30&c=12&op=display_list&vendor=&version=&title=&CVE=")

    if site == 'test':
        urls.append("https://www.securityfocus.com/cgi-bin/index.cgi?o=0&l=30&c=12&op=display_list&vendor=&version=&title=&CVE=")
   
    return urls

def get_tree(url):
    html = requests.get(url).text
    return etree.HTML(html)
    
def get_urls_from_tree(site,tree,n):
    urls = []
    if site == "searchSecurityFocus":
        for i in range(n):
            n = 2*(i+1)
            tree_node_list = tree.xpath('//*[@id="article_list"]/div[2]/a['+str(n)+']')
            for node in tree_node_list:
                link = node.text
                urls.append(link)
    return urls
          
def get_contents(tree):
    contents = {}
    titles = []
    tree_node_list = tree.xpath('//*[@id="vulnerability"]/span')
   
    for node in tree_node_list:
        titles.append(node.text)
    contents['title'] = titles[0]
    content = {}
    for i in range(11):
        entry = tree.xpath('//*[@id="vulnerability"]/table/tr['+str(i+1)+']/td[1]/span')
        data = tree.xpath('//*[@id="vulnerability"]/table/tr['+str(i+1)+']/td[2]')
        if len(entry) and len(data):
            entry_text =entry[0].text.replace('\n','').replace('\t','')
            data_text = data[0].text.replace('\n','').replace('\t','')
            content[entry_text] = data_text
    contents['content'] = content
    return contents

def get_discuss(tree):
    result = []
    lists = tree.xpath('//*[@id="vulnerability"]/text()')
    for item in lists:
        item = item.replace('\n','').replace('\t','')
        if item:
            result.append(item)
    return result

def makedir(dir):
    if not os.path.exists(dir):
        os.mkdir(dir)
    
if __name__ == "__main__":
    count = 0
    start = time.time()
    urls = get_urls('securityFocus')
    makedir('./results')
    #print(time.time()-start)
    for url in urls:
        if count%30 == 0:
            print("page:",count/30)
        tree = get_tree(url)
        report_urls = get_urls_from_tree('searchSecurityFocus',tree,30)
        for report_url in report_urls:
            tree = get_tree(report_url+'/info')
            contents = get_contents(tree)
            discuss=get_discuss(get_tree(report_url+'/discuss')) 
            
            title = contents['title'].replace('/','')
            try:
           
                with open('./result/' + title + '.csv','w') as f:
                    fw = csv.writer(f)
                    content = contents['content']
                    for entry in content.keys():
                        fw.writerow([entry,content[entry]])
                    for d in discuss:
                        if d.replace(' ','')!='':
                            fw.writerow([d])
            except Exception as e:
                print(e)
     