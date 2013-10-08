# Shamelessly borrowed from pyasn1/examples
import sys, string, base64
from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
from pyasn1.codec.der import decoder, encoder
from pyasn1 import error
from pyasn1_modules.rfc2459 import Certificate
from parse import parse_pem
certType = Certificate()

# Read PEM certs from stdin and print them out in plain text

stSpam, stHam, stDump = 0, 1, 2
state = stSpam
certCnt = 0
cert = parse_pem(sys.stdin.read())
print cert.prettyPrint()
