import csv
import os

def write_corpus(chuncked,tar_dir,cert_dir,desc):
    corpus = []
    for parent, dir, filenames in os.walk(cert_dir):
        for filename in filenames:
            lines = open(os.path.join(cert_dir, filename))
            for line in lines:
                line =line.strip('\n\r')
                if line:
                    corpus.append(line)
    #corpus.extend(desc)
    corpus.extend(chuncked)
    with open(tar_dir, 'w') as f:
        for line in corpus:
            f.write(line + '\n')

