from . import server
import os
import subprocess
import multiprocessing
import threading
import time
import collections
MAX_BIND_RETRY = 10
BIND_SLEEP = 0.25
def _run_single_test(certificate_file, key_file, ca_file, script, port, post_fn):
    thread = None
    # Try and bind the socket, since old addresses may still be in use try a few times before giving up(bleh)
    for i in range(MAX_BIND_RETRY):
        event = threading.Event()

        thread = server.ServerThread(certificate_file, key_file, port, event)
        thread.start()
        # wait for the sever to bind the socket
        event.wait()
        if thread.bound:
            break
        thread.join()
        time.sleep(BIND_SLEEP)
    if not thread.bound:
        return None
    try:
        output = subprocess.check_output([script,"localhost","%d" % (port), ca_file], stderr = subprocess.PIPE)
        # Hack to catch some outputs not actually connecting due to internal errors, Weird libraries :(
        if not thread.accepted:
                return None
    except Exception:
        return None
    finally:
        thread.join()
    return post_fn(output)
def run_test(certificate_file, test_scripts, ca_file, key_file, starting_port = 10000, pool_size=4, pool = None):
    results = []
    close = False
    if pool is None:
        pool = multiprocessing.Pool(pool_size)
        close = True
    args = ( (certificate_file, key_file, ca_file, script, starting_port + i) for i, script in enumerate(test_scripts))
    results = pool.map(_run_single_test, args)
    if close:
        pool.close()
    return results
def proxy(arg):
    return arg[0], _run_single_test(*arg[1])
def test_dir(certificate_dir, test_scripts, ca_dir, key_file, starting_port = 10000, ending_port = 20000, pool_size = 4):
    def build_args(certs, scripts):
        i = -1
        for cert in certs:
            for j,script in enumerate(scripts):
                i += 1
                yield (cert, j), (os.path.join(certificate_dir, cert), key_file,
                        os.path.join(ca_dir,script.ca_file), script.script, starting_port + i, script.post_fn)
    pool = multiprocessing.Pool(pool_size)
    certs = os.listdir(certificate_dir)
    map_results = pool.imap(proxy, build_args(certs, test_scripts), 8)
    def const():
        return [ None for i in range(len(test_scripts))]
    results = collections.defaultdict(const)
    for k, v in map_results:
        cert, j = k
        results[cert][j] = v
    pool.close()
    return results
if __name__ == "__main__":
    cert = "./test.crt"
    test_scripts = ["./src/opensslconnect/connect","./src/polarconnect/connect", "./src/gnutlsconnect/connect", "./src/yasslconnect/connect"]
    key = "./keys/localhost.key"
    cafile = "./ca/root-ca.crt"
    res = run_test(cert, test_scripts, cafile, key, pool_size=1, starting_port=30000)
    print(res)
