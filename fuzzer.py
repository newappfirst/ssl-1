import os
import tester
import franken
import sys
import shutil
import hashlib
import time
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
def run_fuzzer(test_scripts, results_dir, temp_base, ca_file, key_file, cert_dir, batch_size = 2000):
    temp_dir = os.path.join(temp_base, "fuzzer-%d/" % (os.getpid()))
    if not os.path.exists(results_dir):
        os.mkdir(results_dir)
    with open("./ca/root-ca.key") as f:
        buf = f.read()
        ca = crypto.load_privatekey(crypto.FILETYPE_PEM, buf)
    with open("./certs/base.crt") as f:
        buf = f.read()
        base = crypto.load_certificate(crypto.FILETYPE_PEM, buf)
    certs = franken.util.load_dir(cert_dir)
    extensions = franken.get_extension_dict(certs)
    while True:
        start = time.time()
        if not os.path.exists(temp_dir):
            os.mkdir(temp_dir)
        genned = franken.generate(certs, base, ca, max_extensions=6, count=batch_size, extensions = extensions)
        franken.util.dump_certs(genned, "fuzzer", temp_dir)
        difs = tester.util.find_discrepancies(temp_dir, test_scripts, ca_file, key_file, ignore_none = True, pool_size=4)
        for cert, error in difs.items():
            error_str = '-'.join(map(str, error))
            out = os.path.join(results_dir, error_str)
            cert_path = os.path.join(temp_dir, cert)
            if not os.path.exists(out):
                os.mkdir(out)
            if len(os.listdir(out)) > MAX_SAMPLES:
                continue
            shutil.move(os.path.join(temp_dir, cert),\
                    os.path.join(out, hashfile(cert_path)))
        shutil.rmtree(temp_dir)
        end = time.time()
        print("Iteration done. Found %d Time Elapsed %f" % (len(difs.keys()), end - start))


if __name__ == "__main__":
    test_scripts = ["./src/opensslconnect/connect","./src/polarconnect/connect", "./src/gnutlsconnect/connect", "./src/yasslconnect/connect"]
    out_dir = "/tmp/results"
    ca_file = "./ca/root-ca.crt"
    key_file = "./keys/base.key"
    cert_dir = sys.argv[1]
    batch_size = 200
    run_fuzzer(test_scripts, out_dir, "/tmp", ca_file, key_file, cert_dir, batch_size)
