"""Command-line tool ffcanew."""

import os.path, sys
import fireflies
import fireflies.crypto
import fireflies.persist
import fireflies.util
from optparse import OptionParser


def main():
    parser = OptionParser(usage="""%prog [options] <path>

Initialize a Fireflies Certificate Authority (CA). This includes creating the
CA's private key and a corresponding self signed X509 certificate. The <path>
arguments spesifies the directory where the repository will be stored.

Files:
  <path>/cacert.pem          - CA's public certificate.
  <path>/private/cakey.pem   - CA's private key""")

    parser.add_option("-e", "--tolerance", dest="tolerance", type="float", default=0.99,
                      help="Byzantine tolerance level. Default=0.99")
    parser.add_option("-p", metavar="NUMBER", dest="pByz", type="float", default=0.20,
                      help="Uniform probability that a member is Byzantine. Default=0.20")
    parser.add_option("-s", metavar="NUMBER", dest="maxGroupSize", type="int", default=1000,
                      help="Maximum size of a group. Default=1000")
    parser.add_option("--password",
                      dest="password", default=None,
                      help="Password to use for reading and writing private keys. If not set, you will be asked for a password when needed.")
    parser.add_option("--nopass",
                      dest="nopass", default=False, action="store_true",
                      help="Do not ecrypt private key.")
    parser.add_option("--ec",
                      dest="ecc", default=False, action="store_true",
                      help="Use Ecliptic Curves crypto.")
    parser.add_option("-n",
                      dest="name", default=None,
                      help="Group name. If not specified the <path> base name will be used.")
    parser.add_option("-o",
                      action="store_true", dest="overwrite", default=False,
                      help="Overwrite CA structure if it exist.")

    (options, args) = parser.parse_args()


    if len(args) != 1:
        parser.print_help()
        sys.exit(0)

    if os.path.exists(args[0]) and not options.overwrite:
        print("CA exists. Please remove or use -o option.")
        sys.exit(0)

    if options.nopass:
        password = None
    else:
        password = options.password or fireflies.crypto.passwordPrompt("CA key password: ")()

    if not options.name:
        options.name = os.path.basename(os.path.normpath(args[0]))

    pkey = fireflies.crypto.makePrivateKey(options.ecc)

    mrings = fireflies.util.numMembershipRings(options.pByz, options.maxGroupSize, options.tolerance, options.maxGroupSize)
    grings = int(fireflies.util.numGossipRings(options.pByz, options.maxGroupSize, options.tolerance))

    cert = fireflies.crypto.makeCACert(pkey, options.name, mrings, grings)

    assert cert.verify(pkey)
    assert cert.verify()
    store = fireflies.persist.Store(args[0])
    store.saveCACert(cert)
    store.saveCaPrivKey(pkey, password)

    print(cert.as_text())

    store = fireflies.persist.Store(args[0])
    c1 = store.loadCACertificate()
    k1 = store.loadCAKey(password)

    assert c1.verify(k1)
    assert c1.verify()


if __name__ == "__main__":
    main()
