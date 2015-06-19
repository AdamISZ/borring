import os, binascii
import bitcoin as btc
from optparse import OptionParser
from hashlib import sha256
import random


def borr_hash(m, pubkey, i, j, is_pubkey=True):
    '''A Sha256 hash of data in the standard 'borromean'
    format. Note that 'pubkey' is the value kG as according to
    kG = sG - eP.
    i,j : the indices to a specific vertex in the graph.
    m - the message to be hashed.
    Returns - the hash.
    '''
    #little hack assuming sizes < 256
    p = btc.encode_pubkey(pubkey,'bin_compressed') if is_pubkey else pubkey
    x = p + m +'\x00'*3 + chr(i) + '\x00'*3 + chr(j) 
    return sha256(x).digest()

def generate_keyfiles(n, m, vf, sf):
    '''Generate a set of public and private keys
    for testing.
    n - the number of OR loops
    m - the number of keys per loop (note: constant in this crude version)
    vf - the file path to which to write the verification keys
    sf - the file path to which to write the signing (private) keys
    '''
    signing_indices = [random.choice(range(m)) for _ in range(n)]
    priv=[]
    with open(sf,'wb') as f:
	for i in range(n):
	    priv.append(os.urandom(32))
	    f.write(binascii.hexlify(priv[i])+'\n')    
    with open(vf,'wb') as f:
	for i in range(n):
	    pubkeys = []
	    for j in range(m):
		if j==signing_indices[i]:
		    p = btc.privtopub(priv[i])
		else:
		    p = btc.privtopub(os.urandom(32))
		p = btc.decode_pubkey(p)
		p = btc.encode_pubkey(p,'bin_compressed')
		pubkeys.append(binascii.hexlify(p))
	    f.write(','.join(pubkeys)+'\n')
    
def import_keys(vf, sf=None):
    '''Import the verification keys;
    one list of pubkeys per loop in hex format, comma separated
    the first pubkey in each list is to be understood as the input
    for the connecting node.    
    vf - the path to the file containing verification pubkeys
    sf - the path to the file containing signing keys, if applicable.
    Returns:
    vks - set of verification keys
    signing_indices - the indices corresponding to the private keys
    sks - the list of private keys
    '''
    vks = {}
    with open(vf,'rb') as f:
	or_loops = f.readlines()
	for i,loop in enumerate(or_loops):
	    raw_pks = loop.strip().split(',')
	    vks[i] = [btc.decode_pubkey(pk) for pk in raw_pks]
    if not sf:
	return (vks, None, None)
    #import the signing private keys;
    #at least one per loop
    with open(sf,'rb') as f:
	raw_sks = f.readlines()
	sks = [binascii.unhexlify(priv.strip()) for priv in raw_sks]
    #check that the signing keys have the right configuration
    if not len(sks)==len(vks):
	raise Exception("Need "+str(len(vks))+" signing keys for a valid signature, got "+str(len(sks)))
    sk_pks = [btc.decode_pubkey(btc.privtopub(sk)) for sk in sks]
    signing_indices = []
    for loop in vks:
	if not len(set(vks[loop]).intersection(set(sk_pks)))==1:
	    raise Exception("Verification key loop does not contain a signing key.")
	signing_indices.append([x for x,item in enumerate(vks[loop]) if item in sk_pks][0])
    #signing keys have right configuration relative to verification keys.
    return (vks, signing_indices, sks)

def get_kG(e, P, s=None):
    if not s:
	s = os.urandom(32)
    sG = btc.fast_multiply(btc.G,btc.decode(s,256))
    minus_eP = btc.fast_multiply(P,btc.decode(e,256))
    return (btc.fast_add(sG, minus_eP), s)    

def get_sig_message(m, vks):
    '''The full message is a sha256 hash
    of the message string concatenated with the
    compressed binary format of all of the verification keys.'''
    full_message = m
    for loop in vks:
	for p in vks[loop]:
	    full_message += btc.encode_pubkey(p,'bin_compressed')
    return sha256(full_message).digest() 

def encode_sig(e, s, le):
    sig = e
    for a in sorted(s):
	for b in s[a]:
	    if le:
		b = b[::-1]
	    sig += b
    return sig

def decode_sig(sig, keyset, le, fmt='bin'):
    '''
    Signature format: e0 (the hash value for the zero index for all loops)
    then s(i,j) , i range over the number of loops, 
    j range over the number of verification keys in the ith loop.
    All 1+i*j values are 32 byte binary variables.'''
    if fmt != 'bin':
	sig = binascii.unhexlify(sig)
    e0 = sig[:32]
    s = {}
    c = 32
    for i in range(len(keyset)):
	s[i]=[None]*len(keyset[i])
	for j in range(len(keyset[i])):
	    s[i][j] = sig[c:c+32]
	    if le: #signature is passed in little endian byte order; reverse
		s[i][j] = s[i][j][::-1]
	    c+=32
    return (e0, s)

if __name__ == '__main__':
    parser = OptionParser(usage='usage: python borring.py [options] message',
	    description='A simple demonstration of Borromean ring signatures using Bitcoin keys.'+
            ' The verification keys file format is: pubkey1,pubkey2,... \\n pubkey1, pubkey2,..' +
            ' where the first pubkey on each line is intended to point to the same node on the directed graph'+
            ' (see Fig 2 in the Borromean ring signatures paper).')
    parser.add_option('-v', '--verify-keys-file', action='store', dest='verify_keys_file',
	    default='verifykeys.txt', help='path to file containing Bitcoin public keys in hex, one per line')
    parser.add_option('-s', '--sign-keys-file', action='store', dest='sign_keys_file',
	    default='signkeys.txt', help='path to file containing signing private keys, in hex')
    parser.add_option('-g','--generate-keys', action='store_true',dest='generate_keys',
                      default=False,help='generate a set of dummy public verification and'+
                      ' private signing keys for testing')
    parser.add_option('-N', '--num-rings', action='store', type='int',dest='nrings',
                      default=5, help='specify number of key rings, to be used with -g')
    parser.add_option('-M', '--keys-per-ring', action='store', type='int', dest='keys_per_ring',
                      default=6, help='specify number of verification keys per ring (same for each), to be used with -g')
    parser.add_option('-w','--write-sig', action='store',dest='write_sig_file',
                      help='write signature to file')
    parser.add_option('-e','--verify-sig', action='store', dest='read_sig_file',
                      help='verify a signature in the specified file, using the verify keys specified in -v')
    parser.add_option('-a','--message-file',action='store', dest='message_file',
                      help='give path to file where message to be signed is stored; alternative to passing message on command line.')
    parser.add_option('-o','--print-modified-message', action='store_true', dest='mod_message',
                       default=False,help='Print the augmented message, which hashes the original message with the verification'+
                       ' keys as specified by -v.')
    parser.add_option('-d','--little-endian-signatures',action='store_true',dest='le_sigs',
                       default=False, help='Output all 32 byte signatures in little endian format')
    (options, args) = parser.parse_args()
	
    if options.generate_keys:
	    print 'generating'
	    generate_keyfiles(options.nrings, options.keys_per_ring, options.verify_keys_file, options.sign_keys_file)
	    exit(0)    
    try:
	if options.message_file:
	    with open(options.message_file,"rb") as f:
		message = binascii.unhexlify(f.read())
	else:
	    message = args[0]    
    except:
	parser.error('Provide a single string argument as a message, or specify message file with -a')
    
    #
    #vks: the set of all verification public keys
    #signing_indices: the index of the vertex for which we have the private key, for each OR loop
    #sks: the set of signing keys (set to None for verification case)
    if options.read_sig_file: options.sign_keys_file = None
    vks, signing_indices, sks = import_keys(options.verify_keys_file, options.sign_keys_file)
    
    #construct message to be signed
    if not options.message_file:
	M = get_sig_message(message, vks)
    else:
	M = message
	print 'working with message'
	print binascii.hexlify(M)
    
    #if option selected, simply print out message which has pubkey commitments
    if options.mod_message:
	print get_sig_message(message, vks)
	exit(0)
	
    if not options.read_sig_file:
	#sign operation
	
	#the set of all (Borromean)  hash values;
	#the vertices of the graph
	e = {}
	
	#the set of all signature values (s(i,j))
	s = {}
	
	#for each OR loop, the index at which we start
	#the signature calculations, the one after the
	#the signing index (the one we have the privkey for)
	start_index = {}
	
	#the random value set as the k-value for the signing index
	k = [os.urandom(32) for i in range(len(vks))] 
	to_be_hashed = ''
	for i, loop in enumerate(vks):
	    e[i]=[None]*len(vks[loop])
	    s[i] = [None]*len(vks[loop])
	    kG = btc.fast_multiply(btc.G, btc.decode(k[i],256))
	    start_index[i] = (signing_indices[i]+1)%len(vks[loop])
	    
	    if start_index[i]==0:
		to_be_hashed += btc.encode_pubkey(kG,'bin_compressed')
		#in this case, there are no more vertices to process in the first stage
		continue
	    
	    e[i][start_index[i]] = borr_hash(M, kG, i, start_index[i])
	    for x in range(start_index[i]+1,len(vks[loop])):
		y,s[i][x-1] = get_kG(e[i][x-1], vks[i][x-1])
		e[i][x] = borr_hash(M,y,i,x)
	    
	    #kGend is the EC point corresponding to the k-value
	    #for the vertex before zero, which will be included in the hash for e0
	    kGend, s[i][len(vks[i])-1] = get_kG(e[i][len(vks[i])-1],vks[i][len(vks[i])-1])
	    to_be_hashed += btc.encode_pubkey(kGend,'bin_compressed')	
	    
	#note that e[i][0] == e0 for all i
	to_be_hashed += M
	e0 = sha256(to_be_hashed).digest()
	for i in range(len(vks)):
	    e[i][0] = borr_hash(M,e0,i,0,is_pubkey=False)
	#continue processing for all vertices after the 0-th, up
	#to the signing index.
	for i,loop in enumerate(vks):
	    for x in range(1,signing_indices[i]+1):
		y, s[i][x-1] = get_kG(e[i][x-1],vks[i][x-1])
		e[i][x] = borr_hash(M,y,i,x)
	    #finally, set the signature at the signing index using the privkey
	    s[i][signing_indices[i]] = \
		btc.encode((btc.decode(k[i],256) - \
		(btc.decode(sks[i],256))*(btc.decode(e[i][signing_indices[i]],256)))%btc.N, 256)
	if options.le_sigs:
	    print "Using little endian signatures"
	final_sig = encode_sig(e0,s, options.le_sigs)
	if options.write_sig_file:
	    print 'writing sig to file: '+options.write_sig_file
	    print 'signature length: '+str(len(final_sig))
	    with open(options.write_sig_file,'wb') as f:
		f.write(final_sig)
    else:
	#verify operation
	#as noted in the paper, this operation is much simpler
	#than signing as we don't treat the signing index as distinct.
	#Because we don't know it!
	with open(options.read_sig_file,'rb') as f:
	    sig = f.read()
	fmt = 'hex' if options.message_file else 'bin'
	received_sig = decode_sig(sig, vks, options.le_sigs,fmt=fmt)
	e = {}	
	e0, s = received_sig
	r0s = ''
	for i, loop in enumerate(vks):
	    e[i] = [None]*len(vks[loop])
	    e[i][0] = borr_hash(M,e0,i,0,is_pubkey=False)
	    for j in range(len(vks[loop])):
		#as in signing, r is the EC point corresponding
		#to the k-value for the last vertex before 0.
		r,dummy = get_kG(e[i][j],vks[i][j],s=s[i][j])
		if j!=len(vks[loop])-1:
		    e[i][j+1] = borr_hash(M,r,i,j+1)
		else:
		    r0s += btc.encode_pubkey(r,'bin_compressed')
	if not e0==sha256(r0s + M).digest():
	    print 'verification failed'
	else:
	    print 'verification success'
	
	print binascii.hexlify(e0)
	print binascii.hexlify(sha256(r0s + M).digest())    
		
	
	
		
    