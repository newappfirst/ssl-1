
import sys, string, base64
from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful, base
from pyasn1.codec.der import decoder, encoder
from pyasn1 import error
from pyasn1_modules.rfc2459 import Certificate, Extensions
import os
import multiprocessing
certType = Certificate()
def tree_dir_multi(path, pool_size=1):
    files = os.listdir(path)
    #files = filter(lambda f : f.endswith(".pem"), files)
    files = map(lambda f : os.path.join(path, f), files)
    pool = multiprocessing.Pool(pool_size)
    return pool.map(tree_file,files)
def tree_file(name):
    try:
        return gen_tree(parse_file(name))
    except:
        return None
def parse_file(name):
    with open(name) as f:
        return parse_pem(f.read())
def parse_pem(pem):
    stSpam, stHam, stDump = 0, 1, 2
    state = stSpam
    for certLine in pem.split('\n'):
        certLine = string.strip(certLine)
        if state == stSpam:
            if state == stSpam:
                if certLine == '-----BEGIN CERTIFICATE-----':
                    certLines = []
                    state = stHam
                    continue
        if state == stHam:
            if certLine == '-----END CERTIFICATE-----':
                state = stDump
            else:
                certLines.append(certLine)
        if state == stDump:
            substrate = ''
            for certLine in certLines:
                substrate = substrate + base64.b64decode(certLine)

            cert = decoder.decode(substrate, asn1Spec=certType)[0]
            return cert
def gen_tree(cert):
    elements = set()
    for sub in cert:
        if sub is None:
            continue
        if isinstance(sub, base.AbstractConstructedAsn1Item):
            elements.add(gen_tree(sub))
        else:
            #Special case Object IDs so we can disambiguate extensions and such
            #otherwise contents are ignored
            if isinstance(sub, univ.ObjectIdentifier):
                elements.add(sub.subtype())
            else:
                elements.add(str(cert.__class__))
    return (str(cert.__class__), frozenset(elements))
def parse_dir(directory):
    certs = {}
    for name in os.listdir(directory):
        if not name.endswith(".pem"):
            continue
        with open(os.path.join(directory,name)) as f:
            pem = f.read()
            cert = parse_pem(pem)
            certs[name] = cert
    return certs
def get_extensions(tree):
    exts = set()
    _get_extensions(tree, exts)
    return frozenset(exts)
def _get_extensions(tree, extensions):
    #hacky :(
    if not isinstance(tree[1], frozenset):
        return
    for sub in tree[1]:
        if sub[0] == 'pyasn1_modules.rfc2459.Extensions':
            extensions.add(sub[1])
        else:
            _get_extensions(sub, extensions)
