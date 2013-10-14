import os
import tester
import franken
import sys
import shutil
import hashlib
from OpenSSL import crypto
MAX_SAMPLES = 512
def hashfile(filepath):
    sha1 = hashlib.sha1()
    f = open(filepath, 'rb')
    try:
        sha1.update(f.read())
    finally:
        f.close()
    return sha1.hexdigest()
test_scripts = ["./src/opensslconnect/connect","./src/polarconnect/connect", "./src/gnutlsconnect/connect", "./src/yasslconnect/connect"]
out_dir = "/tmp/results"
temp_dir = "/tmp/fuzzer-%d/" % (os.getpid())
ca_file = "./ca/root-ca.crt"
key_file = "./keys/localhost.key"
cert_dir = sys.argv[1]
batch_size = 2000
if not os.path.exists(out_dir):
    os.mkdir(out_dir)
with open("./ca/root-ca.key") as f:
    buf = f.read()
    ca = crypto.load_privatekey(crypto.FILETYPE_PEM, buf)
with open("./certs/localhost.crt") as f:
    buf = f.read()
    base = crypto.load_certificate(crypto.FILETYPE_PEM, buf)
certs = franken.util.load_dir(cert_dir)
extensions = franken.get_extension_dict(certs)
while True:
    if not os.path.exists(temp_dir):
        os.mkdir(temp_dir)
    genned = franken.generate(certs, base, ca, max_extensions=6, count=batch_size, extensions = extensions)
    franken.util.dump_certs(genned, "fuzzer", temp_dir)
    difs = tester.util.find_discrepancies(temp_dir, test_scripts, ca_file, key_file, ignore_none = True)
    for cert, error in difs.items():
        error_str = '-'.join(map(str, error))
        out = os.path.join(out_dir, error_str)
        cert_path = os.path.join(temp_dir, cert)
        if not os.path.exists(out):
            os.mkdir(out)
        if len(os.listdir(out)) > MAX_SAMPLES:
            continue
        shutil.move(os.path.join(temp_dir, cert),\
                os.path.join(out, hashfile(cert_path)))
    shutil.rmtree(temp_dir)
    print "Iteration done, found %d" % len(difs.keys())



