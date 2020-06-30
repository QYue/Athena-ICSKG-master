

from utils.readData import *
from gensim.models import word2vec
import gensim
import logging
import scipy
import numpy as np

def similarity(v1,v2):
    #return np.linalg.norm(v1-v2)
    return 1/2 +1/2*(np.dot(v1,v2)/(np.linalg.norm(v1)*np.linalg.norm(v2)))
    #return 1-scipy.spatial.distance.cosine(v1,v2)


# train and save model for word embedding
def model_train(train_file_name, save_model_file):
    logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s', level=logging.INFO)
    sentences = word2vec.Text8Corpus(train_file_name)
    model = gensim.models.Word2Vec(sentences, sg=1,size=256, sample=0.01,window=2,iter=5,min_count=2,negative=15)
    model.save(save_model_file)
    model.wv.save_word2vec_format(save_model_file + ".bin", binary=True)



def get_emb_model(corpus_path, save_model_path):
    if os.path.exists(save_model_path):
        model = word2vec.Word2Vec.load(save_model_path)
    else:
        model = model_train(corpus_path, save_model_path)
    return model

def train_align_matrix(model,kge_path='../../result/embedding/TransR/'):

    entvec = read_entvec(os.path.join(kge_path, 'ent_embedding.tsv'))
    ent_ind = read_ent(os.path.join(kge_path, 'ent_labels.tsv'))
    if 'Affected Version' in ent_ind.keys():
        version_ind = ent_ind['Affected Version']
    if 'Product' in ent_ind.keys():
        product_ind = ent_ind['Product']

    product_kge_vec = entvec[product_ind]
    version_kge_vec = entvec[version_ind]

    product_vec = model.wv.__getitem__('<Product>')

    version_vec = model.wv.__getitem__('<Affected_Version>')
    kg = np.array([product_kge_vec, version_kge_vec])

    text = np.array([product_vec, version_vec])
    align = scipy.linalg.orthogonal_procrustes(text, kg, check_finite=True)[0]
    return align,  product_kge_vec,  version_kge_vec


def  extract_ap(item, align,model, p_kge_vec, v_kge_vec,t=0.75):
    desc = item["Tokenized Sentence"]
    entities = list(item['Entities'].values())
    entities = [x.strip() for x in entities if x]
    ap = []
    words = desc.split(' ')
    labels = np.array(len(words))
    for i,w in enumerate(words):
        if w.replace('_', ' ') in entities or w not in model.wv.vocab:
            continue
        v = model.wv.__getitem__(w)
        aligned_v = np.matmul(v, align)

        sim_pro = similarity(aligned_v, p_kge_vec)
        sim_ver = similarity(aligned_v, v_kge_vec)
        if sim_pro > sim_ver and sim_pro >= t:
            labels[i] = 'p'
        elif sim_ver > sim_pro and sim_ver >= t:
            if i and labels[i-1]=='p':
              ap.append( {"pname": words[i-1], 'version': w})
    return ap
