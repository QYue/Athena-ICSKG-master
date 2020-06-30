
from utils.config import *
# import spacy
# from benepar.spacy_plugin import BeneparComponent

# nlp = spacy.load('en')
# nlp.add_pipe(BeneparComponent('benepar_en'))
CERT_DIR = 'seedKG/cert_0628.json'
ST_DIR = 'SecurityTracker/ICS'
SF_DIR = 'SecurityFocus/ICS'
NVD_DIR = 'NVD'

def main():
    KG = KnowledgeGraph(check_cwe=0)
    KG.buildKG(CERT_DIR, ST_DIR, SF_DIR, NVD_DIR)
    KG.report_inconsistency()
    KG.unstructredIE('embedding/corpus.txt','embedding/model.txt')

if __name__ == "__main__":
    main()