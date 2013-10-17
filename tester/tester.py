from . import server
import os
import subprocess
import multiprocessing
import threading
import time
MAX_BIND_RETRY = 10
BIND_SLEEP = 0.25
def _run_single_test(tupl):
    certificate_file, key_file, ca_file, script, port = tupl
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
        output = subprocess.check_output([script,"localhost","%d" % (port), ca_file])
    except Exception:
        return None
    finally:
        thread.join()
    # Simple result check for now because :effort:
    return output.strip()
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
def test_dir(certificate_dir, test_scripts, ca_file, key_file, starting_port = 10000, ending_port = 20000, pool_size = 4):
    port = starting_port
    pool = multiprocessing.Pool(pool_size)
    results = dict()
    for cert in os.listdir(certificate_dir):
        cert_path = os.path.join(certificate_dir, cert)
        results[cert] = run_test(cert_path, test_scripts, ca_file, key_file, starting_port, pool = pool)
        #simple port updating/wraparound because :effort:
        port += len(test_scripts)
        if port > ending_port:
            port = starting_port
    pool.close()
    return results
if __name__ == "__main__":
    cert = "./test.crt"
    test_scripts = ["./src/opensslconnect/connect","./src/polarconnect/connect", "./src/gnutlsconnect/connect", "./src/yasslconnect/connect"]
    key = "./keys/localhost.key"
    cafile = "./ca/root-ca.crt"
    res = run_test(cert, test_scripts, cafile, key, pool_size=1, starting_port=30000)
    print(res)
