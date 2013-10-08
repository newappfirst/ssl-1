from OpenSSL import crypto
import random
import collections
def get_extension_dict(certs):
    d = collections.defaultdict(set)
    for cert in certs:
        extensions = get_extensions(cert)
        for extension in extensions:
            d[extension.get_short_name()].add(extension)
    for k in d.keys():
        d[k] = list(d[k])
    return d
def get_extensions(cert):
    return  [cert.get_extension(i) \
                for i in range(0, cert.get_extension_count())]
def generate(certificates, base_cert, signing_key, max_extensions=20, count=1):
    certs = []
    extensions = get_extension_dict(certificates)
    max_extensions = min(max_extensions, len(extensions.keys()))
    for i in range(count):
        cert = crypto.X509()
        # handle the boring entries
        cert.set_pubkey(base_cert.get_pubkey())
        pick = random.choice(certificates)
        cert.set_notAfter(pick.get_notAfter())
        pick = random.choice(certificates)
        cert.set_notBefore(pick.get_notBefore())
        pick = random.choice(certificates)
        cert.set_serial_number(pick.get_serial_number())
        pick = random.choice(certificates)
        cert.set_issuer(pick.get_issuer())
        pick = random.choice(certificates)
        cert.set_subject(pick.get_subject())

        # handle the extensions
        # Currently we chose [0,max] extension types
        # then pick one entry randomly from each type
        # pyOpenSSL doesn't really support poking into the data
        # so currently avoiding doing anything inside extensions
        print len(extensions.keys())
        sample = random.randint(0, max_extensions)
        choices = random.sample(extensions.keys(), sample)
        new_extensions = [random.choice(extensions[name]) for name in choices]
        cert.add_extensions(new_extensions)

        cert.sign(signing_key,"sha1")
        certs.append(cert)
    if count == 1:
        return certs[0]
    else:
        return certs
