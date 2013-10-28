import os
from OpenSSL import crypto
def dump_certs(certs, prefix, path):
    for i,cert in enumerate(certs):
        key,certs = cert
        with open(os.path.join(path, "%s-%d.pem" % (prefix, i)), "w") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
            for cert in certs:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
def load_dir(path):      
    certs = []        
    files = os.listdir(path)                                               
    files = map(lambda f : os.path.join(path, f), files)
    for file in files:
        with open(file) as f:
            buf = f.read()
            certs.append(crypto.load_certificate(crypto.FILETYPE_PEM, buf))
    return certs
