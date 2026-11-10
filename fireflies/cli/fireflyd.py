"""Command-line tool fireflyd: run a Fireflies member."""

import warnings

warnings.filterwarnings(action="ignore", category=DeprecationWarning)

from twisted.internet import reactor, task
import errno, random, sys, os.path, logging, socket, os
import logging.handlers
import fireflies
import fireflies.fd, fireflies.gossip, fireflies.group
from fireflies import state, crypto, group, stats, persist


random.seed()

def main():
    groupCert = groupKey = myCert = myKey = myNote = None
    
    from optparse import OptionParser
    parser = OptionParser(usage="""%prog [options] <path> <path 1> ... <path n>
    
    Deamon that maintains a basic Fireflies mesh. The <path> arguments refers
    to the path that the deamon will store its data. <path 1>...<path n>
    reffers to supplemental Fireflies repositories from which the deamon will
    search for certificates, notes, and accusations when bootstrapping.   

    For the deamon to run it must posess the following:
       - The CA's X509 certificate, 
       - A X509 member certificate containing an usable network address.
       - A private key that corresponds to an usable certificate.

    Upon startup, the daemon will first search for a certificate containing
    the specified network address. If found, the deamon will search for the
    private key matching that certificate. If either an usable certificate or
    the corresponding private key cannot be found, the deamon cannot be
    started. For testing purposes, you can provide the daemon with the CA's
    private key. The deamon will then create its own certificates if needed.
    Note that this behaviour undermines the security of Fireflies and should
    only be used for testing purposes.
    
    Files:
      - <path>/private/<keyid>.pem    - Private key
      - <path>/private/cakey.pem      - CA's private key
      - <path>/certs/<ip:port>.pem    - Member certificates
      - <path>/cacert.pem             - CA's certificate    
    """, version="%%prog %s" % fireflies.version)
    hostaddr = socket.gethostbyname(socket.getfqdn())
    parser.add_option("-a", "--address", dest="address",
                      help="Bind to ADDRESS. Defaults to %s." % hostaddr, default=hostaddr )
    parser.add_option("-p", "--port", dest="port", type="int",
                      help="Bind PORT. Defaults to %s." % fireflies.defaultConfig['port'], default=fireflies.defaultConfig['port'])
    parser.add_option("--capriv",
                      dest="capriv", default=None,
                      help="Path to CA's repository. This enables fireflyd to create a X509 certificate for itself.")
    parser.add_option("--cacert",
                      dest="cacert", default=None,
                      help="Import the CA's certificate from this file.")    
    parser.add_option("-l", "--logdir", dest="logdir", 
                      help="When daemon, write logs to LOGDIR.", default="./")
    parser.add_option("-g", "--group", dest="group", default=None,
                      help="Run in group.")
    parser.add_option("-u", "--user", dest="user", default=None,
                      help="Run as USER.")
    parser.add_option("-m", "--max", dest="max", type="int", default=1000,
                      help="Do not use more than MAX notes from the cache.")
    parser.add_option("-d", "--daemon",
                      action="store_true", dest="daemon", default=False,
                      help="Run as daemon.")
    parser.add_option("-o", "--overwrite",
                      action="store_true", dest="overwrite", default=False,
                      help="Overwrite existing X509 structures on startup.")
    parser.add_option("--readonly",
                      action="store_true", dest="storero", default=False,
                      help="Do not write state to store.")
    parser.add_option("-r", "--rundir",
                      dest="rundir", default="./",
                      help="Rundir.")
    
    parser.add_option("--verbose",
                      action="store_true", dest="verbose", default=False,
                      help="Verbose output.")
    parser.add_option("-b", "--byzantine",
                      dest="byzantine", default=None,
                      help="Checks in this file if the member is supposed to be Byzantine.")
    parser.add_option("--password",
                      dest="password", default=None,
                      help="Password to use. If not set, you will be asked for a password when loading and saving private keys.")
    parser.add_option("--nopass",
                      dest="nopass", default=False, action="store_true", 
                      help="Do not use a password to protect private keys.")
    parser.add_option("--ec", 
                      dest="ecc", default=False, action="store_true",
                      help="Use elliptic curve crypto.")


    (options, args) = parser.parse_args()
    
    if len(args) < 1:
        parser.print_help()
        sys.exit()

    myAddress = "%s:%d" % (options.address, options.port)

    # password is used to read keys, keyPassword to write them.
    password = options.password or crypto.passwordPrompt("Key password: ")
    keyPassword = None if options.nopass else password
        

    # Change user/group
    if options.user:
        import pwd
        os.seteuid(pwd.getpwnam(options.user)[2])
    if options.group:
        import grp
        os.seteuid(grp.getgrnam(options.group)[2])
       
    # Set logging verbosity
    l = logging.getLogger()
    if options.verbose:
        l.setLevel(logging.DEBUG)
    else:
        l.setLevel(logging.INFO)
        
    #Check byzantine setting.
    byzantine = 0
    if options.byzantine:
        for line in open(options.byzantine).readlines():
            line = line.strip()
            if line == "": continue
            
            name, behaviour = line.split()
            
            if name == options.address:
                byzantine = int(behaviour)
                break
                                               
    #
    # Load own keys and notes.
    #
    # The first argument can either be a CA certificate, or a CA
    # Key. If given the key, we can make our own member certificates.

  # Become a daemon?
    if options.daemon:
        if os.fork(): 
            os._exit(0)
        os.setsid() #???
        os.umask(0o77)
        for i in range(3):
            try:
                os.close(i)
            except OSError as e:
                if e.errno != errno.EBADF:
                    raise
        log_hdlr = logging.handlers.RotatingFileHandler(os.path.join(options.logdir, myAddress), "a", 100000000, 10)
    else:
        log_hdlr = logging.StreamHandler(sys.stdout)
                
    formatter = logging.Formatter('%(asctime)s %(message)s', "%d-%m-%H:%M:%S")
    log_hdlr.setFormatter(formatter)
    logging.getLogger().addHandler(log_hdlr)

    # Init Store.
    try:
        store = persist.Store(args[0])
        extStores = [persist.Store(x) for x in args[1:]]
    except Exception as why:
        print("Unable to initialize store.", why)
        sys.exit(0)

         
        
    # Load Group Cert 
    if store.hasCACertificate():    
        groupCert = store.loadCACertificate()
    else:
        for extstore in extStores:
            if extstore.hasCACertificate():
                groupCert = extstore.loadCACertificate()
                store.saveCACert(groupCert)
                logging.info("Import group certificate from %s", extstore.fileCaCert)
                break
        if not groupCert:    
            if options.cacert:
                groupCert = crypto.Certificate.load(options.cacert)
                store.saveCACert(groupCert)
                logging.info("Import group certificate from %s", options.cacert)
            else:                
                logging.error("Unable to load group certificate.")
                sys.exit(0)

        
    # Load Member Certificate
    if store.hasMemberCertificateWithAddress(myAddress):        
        myCert = store.loadMemberCertificateByAddress(myAddress)
    else:

        for extstore in extStores:
            if extstore.hasMemberCertificateWithAddress(myAddress):
                myCert = extstore.loadMemberCertificateByAddress(myAddress)       
                break

        # Try to generate certificate.
        if not myCert:        
            if not options.capriv:
                print("Unable to find or create member certificate for address=%s" % myAddress)
                sys.exit(0)

            groupKey = crypto.PrivateKey.load(options.capriv, password)
            if not groupCert.verify(groupKey): raise ValueError("CA cert and CA key do not match.")

            if options.ecc:
                myKey = fireflies.crypto.makePrivateECKey()
            else:            
                myKey = fireflies.crypto.makePrivateRSAKey()
            req = fireflies.crypto.makeRequest(myAddress, myKey)
            myCert = store.newMemberCertificate(req, groupKey)          
            assert myCert.verify(groupKey)
            #print myCert.as_text()
            logging.info("Saving private key %s", store.filenameKey(myKey))
            logging.info("Saving new certificate %s", store.filenameCertificate(myCert))
            store.saveMemberCertificate(myCert)
            store.savePrivateKey(myKey, keyPassword)

    if not store.hasKeyForCertificate(myCert):
        for extstore in extStores:
            if extstore.hasKeyForCertificate(myCert):
                logging.info("Found suitable key in %s", extstore.dirRoot)
                store.savePrivateKey(extstore.loadPrivateKeyForCert(myCert, password), keyPassword)
                break
                                
    try:
        myKey = store.loadPrivateKeyForCert(myCert, password)
    except KeyError as why:
        print("Unable to load private key.", why)
        sys.exit()

    try:
        myNote = store.loadNoteFromCert(myCert)
    except KeyError as why:
        print("Cannot find note. Will create new one.", why)
            
    assert myCert.verify(groupCert.get_pubkey())
        
    mgroup = group.Group(groupCert, myKey, myCert, myNote)
    mgroup.badness = byzantine    
    
    logging.info("Me = %s on %s badness=%d", mgroup.getMe().identity, mgroup.getMe().getAddress(), mgroup.badness)

    def updateNote():
        logging.info("Updating note after startup.")
        mgroup.badness = byzantine           
        n = mgroup.getMe().nextNote()
        n.sign(mgroup.getMyKey())
        mgroup.view.addNote(n)
    
    reactor.callLater(10, updateNote)            
    
    fd = fireflies.fd.FailureDetector(mgroup)
    gossip = fireflies.gossip.Gossip(mgroup)


    #
    # Load other certificates and notes.   
    #
    
    for cert in store.loadMemberCertificates():
        mgroup.view.addCertificate(cert)
        
    for note in store.loadNotes():
        try:
            mgroup.view.addNote(note)
        except ValueError as e:
            print("Error loading note %s %s" % (note, e))
                    
    for acc in store.loadAccusations():
        try:
            mgroup.view.addAccusation(acc)
        except:
            pass

   # Import membership data from other stores

    for extstore in extStores:
        logging.info("Importing data from %s", extstore.dirRoot)
        for cert in extstore.loadMemberCertificates(): 
            mgroup.view.addCertificate(cert)
                
        for note in extstore.loadNotes(): 
            mgroup.view.addNote(note)
                
        for accu in extstore.loadAccusations(): 
            mgroup.view.addAccusation(accu)

    store.saveGroup(mgroup)

    bogomips = 0

    try:
        lines = open("/proc/cpuinfo").readlines()
    except Exception:
        logging.warning("unable to open /proc/cpuinfo.")
    else:
        while 1:
            if len(lines) == 0:
                logging.warning("unable to find bogomips value.")
                break

            line = lines.pop(0)
            if not line.startswith("bogomips"): continue
            bogomips = line.split(":")[1]
            bogomips = bogomips.strip()
            bogomips = float(bogomips)
            logging.info("calculating load using bogomips=%f", bogomips)
            break

    global netErrOld, netErrNew 
    netErrOld = netErrNew = stats.Stats()
    def checkUDPError():
        global netErrOld, netErrNew
        netErrNew = fireflies.group.collectStatistic(mgroup)
        diff = netErrNew - netErrOld
        if diff.udpR == 0:
            logging.error("No incoming UDP. Exiting")
            reactor.stop()

    global sold, snew
    sold = snew = stats.Stats()
    sold.cputime = os.times()[0] * bogomips
    t = fireflies.time.time()
        
    def doCheckpoint():
        global sold, snew
        snew = fireflies.group.collectStatistic(mgroup)
        snew.cputime = os.times()[0] * bogomips
        sdiff = snew - sold
        sdiff.members = snew.members
        sdiff.fmembers = snew.fmembers
        logging.info("checkpoint %s %d %d" % (str(sdiff), snew.members, snew.fmembers))
        sold = snew 

    def doWriteState():
        try:
            store.clear()
            store.saveGroup(mgroup)
            logging.info("writing state.")
        except Exception as why:
            logging.error("Failed saving group.")

    def persistMyOwnNote(name, note, s):
        assert name == "data.note"
        if not isinstance(note, state.Note): raise ValueError
        if s == False: return # Note is deleted, so we don't care.
        if note.identity == mgroup.getMe().identity:
            store.saveNote(note)
            
    mgroup.registerEventHandler("data.note", persistMyOwnNote)

    def failback(msg):
        logging.exception(msg)
        
    checkpointTask = task.LoopingCall(doCheckpoint)
    checkpointTask.start(10).addErrback(failback)

    noUDPCheck = task.LoopingCall(checkUDPError)
    noUDPCheck.start(5*60, False)

    writeStateTask = task.LoopingCall(doWriteState)
    writeStateTask.start(10*60, False)
  

    reactor.callLater(0, mgroup.startService)

    try:
        reactor.run()
    except Exception as why:
        logging.exception("reactor crash? %s", why)

    if not options.storero: store.saveGroup(mgroup)

    logging.info("Shutdown")


if __name__ == "__main__":
    main()
