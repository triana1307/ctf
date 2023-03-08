#!/usr/bin/python2
import sys, getopt, socket
BUFFER_SIZE = 2048
port=9999
host="192.168.1.75"
def checkpoint2_oracle(plaintext, sock):
    if (plaintext == ""): plaintext = "NULL"
    sock.send(plaintext)
    resp = sock.recv(BUFFER_SIZE)
    return resp.decode("hex")

def splitIntoBlocks(data, blockSize):
    o = []
    while(data):
        o.append(data[0:blockSize])
        data = data[blockSize:]
    return o

def addToDecryptionDictionary(prefixStr, crackDict, blockNumber,
blockSize, sock):
    for c in range(256):
        block = getHexBlock(checkpoint2_oracle(prefixStr+chr(c),
sock), blockNumber, blockSize)
        crackDict[block] = chr(c)

def getHexBlock(ciphertext, i, blockSize):
    block = ciphertext.encode('hex')[(i*blockSize)*2:(i+1)*blockSize*2]
    return block

def isECB(ciphertext):
    ciphertext = ciphertext.encode('hex')
    blocks = len(ciphertext)/32
    for i in range(0,blocks):
        for j in range(i+1,blocks):
            str1=ciphertext[i*32:(i+1)*32]
            str2=ciphertext[j*32:(j+1)*32]
            if str2=="":
                continue
            if str1 == str2:
                return True
    return False

print "Connecting to port " + str(port)
# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    #print >>sys.stderr, 'connecting to %s port %s' % server_address
    sock.connect(server_address)
    print 'Connected to %s port %s' % server_address
except socket.error:
    print >>sys.stderr, "Could not connect to the server"
    exit(1)

print sock.recv(2048)

A="A"
ctxtlen=len(checkpoint2_oracle("", sock))
blockSize=-1
for i in range(64):
    ctxt = checkpoint2_oracle(A*i, sock)
    if len(ctxt) > ctxtlen:
        blockSize = len(ctxt)-ctxtlen
        break
if (isECB(checkpoint2_oracle(A*(3*blockSize), sock))):
    usingECB=True
else:
    print "Not using ECB"
    exit(1)

blocks = splitIntoBlocks(checkpoint2_oracle(A*(3*blockSize),sock).encode('hex'), blockSize*2)

x=-1
y=-1
for i, block in enumerate(blocks):
    if (blocks[i] == blocks[i+1]):
        x=i
        y=i+1
        break

offset=-1
for i in range(blockSize):
    testplaintext = A*2*blockSize + A*i + 'Z'
    #print testplaintext
    ciphertext = checkpoint2_oracle(testplaintext, sock)
    blocks=splitIntoBlocks(ciphertext.encode('hex'), blockSize*2)
    if (blocks[x] == blocks[y]):
        offset=i
        break

print "Offset is ", offset
numberOfUnknownBlocks = len(checkpoint2_oracle("", sock))/blockSize - x
crack={}
decryptedMessage = ""

for j in range(numberOfUnknownBlocks+1):
    for i in range(blockSize):
        addToDecryptionDictionary(A*offset + A*(blockSize-i-1)+decryptedMessage, crack, j+x, blockSize ,sock)
        block = getHexBlock(checkpoint2_oracle(A*offset + A*(blockSize-i-1), sock), j+x, blockSize)
        if block in crack:
            if (crack[block] == '\x01'):
               break
        decryptedMessage += crack[block]
    else:
            break
            
print "Decrypted:"
print decryptedMessage.rstrip('\n') 
