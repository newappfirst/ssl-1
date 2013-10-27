from OpenSSL import crypto
import random
import collections
def get_extension_dict(certs):
    d = collections.defaultdict(dict)
    for cert in certs:
        extensions = get_extensions(cert)
        for i,extension in enumerate(extensions):

            """
            PyOpenSSL's get_short_name return UNKN for all unknown extensions
            This is bad for a mapping, so I added a get_oid function.
            See get_oid.patch

            """
            # stupid ghetto set to avoid func call overheads of wrapping :(
            d[extension.get_oid()][extension.get_data()] = extension
    for k in d.keys():
        d[k] = d[k].values()
    return d
def get_extensions(cert):
    return  [cert.get_extension(i) \
                for i in range(0, cert.get_extension_count())]
def generate_cert(certificates, signing_key, issuer, max_extensions, extensions, flip_probability=0.25):
    cert = crypto.X509()
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 512)
    # handle the boring entries
    cert.set_pubkey(pkey)
    cert.set_issuer(issuer)
    pick = random.choice(certificates)
    cert.set_notAfter(pick.get_notAfter())
    pick = random.choice(certificates)
    cert.set_notBefore(pick.get_notBefore())
    pick = random.choice(certificates)
    cert.set_serial_number(pick.get_serial_number())
    pick = random.choice(certificates)
    cert.set_subject(pick.get_subject())

    # handle the extensions
    # Currently we chose [0,max] extension types
    # then pick one entry randomly from each type
    # pyOpenSSL doesn't really support poking into the data
    # so currently avoiding doing anything inside extensions
    # TODO: Multiple extensions of the same type?
    sample = random.randint(0, max_extensions)
    choices = random.sample(extensions.keys(), sample)
    new_extensions = [random.choice(extensions[name]) for name in choices]
    for extension in new_extensions:
        if random.random() < flip_probability:
            extension.set_critical(1 - extension.get_critical())

    cert.add_extensions(new_extensions)
    cert.sign(signing_key,"sha1")
    return pkey, cert
def generate(certificates, base_cert, ca_key, max_extensions=20, count=1, extensions = None, flip_probability=0.25):
    certs = []
    if extensions is None:
        extensions = get_extension_dict(certificates)
    max_extensions = min(max_extensions, len(extensions.keys()))
    for i in range(count):
        cert = generate_cert(certificates, ca_key, base_cert.get_issuer(), max_extensions, extensions, flip_probability)
        certs.append(cert)
    return certs
