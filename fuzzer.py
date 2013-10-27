import os
import tester
import franken
import sys
import shutil
import hashlib
import time
from collections import namedtuple
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
def run_fuzzer(test_scripts, results_dir, temp_base, ca_dir, cert_dir, batch_size = 2000):
    temp_dir = os.path.join(temp_base, "fuzzer-%d/" % (os.getpid()))
    if not os.path.exists(results_dir):
        os.mkdir(results_dir)
    with open("./ca/root-ca.key") as f:
        buf = f.read()
        ca = crypto.load_privatekey(crypto.FILETYPE_PEM, buf)
    with open("./certs/base.crt") as f:
        buf = f.read()
        base = crypto.load_certificate(crypto.FILETYPE_PEM, buf)
    print "Loading certs..."
    certs = franken.util.load_dir(cert_dir)
    print "Building extension map..."
    extensions = franken.get_extension_dict(certs)
    print "Starting testing..."
    while True:
        start = time.time()
        if not os.path.exists(temp_dir):
            os.mkdir(temp_dir)
        genned = franken.generate(certs, base, ca, max_extensions=6, count=batch_size, extensions = extensions)
        franken.util.dump_certs(genned, "fuzzer", temp_dir)
        difs = run_dir(test_scripts, results_dir, temp_dir, ca_dir)
        end = time.time()
        print("Iteration done. Found %d Time Elapsed %f" % (len(difs.keys()), end - start))
def run_dir(test_scripts, out_dir, in_dir, ca_dir):
    difs = tester.util.find_discrepancies(in_dir, test_scripts, ca_dir, ignore_none = True, pool_size=1, starting_port=33000, ending_port=35000)
    for cert, error in difs.items():
        error_str = '-'.join(map(str, error))
        out = os.path.join(out_dir, error_str)
        cert_path = os.path.join(in_dir, cert)
        if not os.path.exists(out):
            os.mkdir(out)
        if len(os.listdir(out)) > MAX_SAMPLES:
            continue
        shutil.move(os.path.join(in_dir, cert),\
                os.path.join(out, hashfile(cert_path)))
    return difs

def base_post_fn(output):
    return output.strip()
def crypt_post_fn(output):
    lines = output.split('\n')
    return lines[0].strip()
if __name__ == "__main__":
    out_dir = "/tmp/results"
    ca_dir = "./ca/"
    cert_dir = sys.argv[1]
    batch_size = 10
    script = namedtuple("script",["script","post_fn", "ca_file"])
    test_scripts = [ script("./src/opensslconnect/connect", base_post_fn, "root-ca.crt"),\
            script("./src/polarconnect/connect", base_post_fn, "root-ca.crt"),\
            script("./src/gnutlsconnect/connect", base_post_fn, "root-ca.crt"),\
            script("./src/yasslconnect/connect", base_post_fn, "root-ca.crt"),\
            script("./src/matrixsslconnect/connect", base_post_fn, "root-ca.crt"),\
            script("./src/cryptlibconnect/connect", crypt_post_fn, "root-ca.crt"),\
            ]
    run_fuzzer(test_scripts, out_dir, "/tmp", ca_dir, cert_dir, batch_size)
