import tester
import operator

def find_discrepancies(certificate_dir, test_scripts, ca_file, key_file\
        ,starting_port = 10000, ending_port = 20000, pool_size = 4, ignore_none = False):
    base_results = tester.test_dir(certificate_dir, test_scripts, ca_file, key_file, starting_port, ending_port, pool_size)
    if ignore_none:
        new_res = dict()
        for k,v in base_results.items():
            new_res[k] = filter(lambda x : not x is None, v)
        results = new_res
    else:
        results = base_results
    disc = { k : base_results[k] for k,v in results.items() if not all(v[0] == e or e != '0' for e in v)}
    return disc
