import os
from OpenSSL import crypto
def dump_certs(certs, prefix, path):
    for i,cert in enumerate(certs):
        with open(os.path.join(path, "%s-%d.pem" % (prefix, i)), "w") as f:
            buf = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
            f.write(buf)
def load_dir(path):      
    certs = []        
    files = os.listdir(path)                                               
    files = map(lambda f : os.path.join(path, f), files)
    for file in files:
        with open(file) as f:
            buf = f.read()
            certs.append(crypto.load_certificate(crypto.FILETYPE_PEM, buf))
    return certs
