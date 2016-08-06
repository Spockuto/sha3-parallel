import sys
import time
import binascii
from multiprocessing import Pool
import multiprocessing
from pathos.multiprocessing import ProcessingPool

class Keccak(object):

    def __init__(self):
        pass

    def KeccakF1600onLanes(self , lanes):
        R = 1
        for round in range(24):
            # theta step
            C = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
            D = [C[(x+4)%5] ^ self.ROL64(C[(x+1)%5], 1) for x in range(5)]
            lanes = [[lanes[x][y]^D[x] for y in range(5)] for x in range(5)]
            # Rho and Phi Step
            (x, y) = (1, 0)
            current = lanes[x][y]
            for t in range(24):
                (x, y) = (y, (2*x+3*y)%5)
                (current, lanes[x][y]) = (lanes[x][y], self.ROL64(current, (t+1)*(t+2)//2))
            # chi step
            for y in range(5):
                T = [lanes[x][y] for x in range(5)]
                for x in range(5):
                    lanes[x][y] = T[x] ^((~T[(x+1)%5]) & T[(x+2)%5])
            # iota step
            for j in range(7):
                R = ((R << 1) ^ ((R >> 7)*0x71)) % 256
                if (R & 2):
                    lanes[0][0] = lanes[0][0] ^ (1 << ((1<<j)-1))
        return lanes

    def load64(self, b):
        return sum((b[i] << (8*i)) for i in range(8))

    def store64(self, a):
        return list((a >> (8*i)) % 256 for i in range(8))

    def ROL64(self, a, n):
        return ((a >> (64-(n%64))) + (a << (n%64))) % (1 << 64)

    def makeSerialString(self, input):
        return "{0:0x}".format(int(input, 2)) if input != '' else ''

    def KeccakF1600(self, state):
        lanes = [[self.load64(state[8*(x+5*y):8*(x+5*y)+8]) for y in range(5)] for x in range(5)]
        lanes = self.KeccakF1600onLanes(lanes)
        state = bytearray(200)
        for x in range(5):
            for y in range(5):
                state[8*(x+5*y):8*(x+5*y)+8] = self.store64(lanes[x][y])
        return state

    def Keccak(self, rate, capacity, inputBytes, delimitedSuffix, outputByteLen):
        #inputBytes = "{0:0x}".format(int(inputBytes, 2)) if inputBytes != '' else ''
        inputBytes = bytearray(binascii.unhexlify(inputBytes))
        inputBytes = inputBytes[:len(inputBytes)]
        outputBytes = bytearray()
        state = bytearray([0 for i in range(200)])
        rateInBytes = rate//8
        blockSize = 0
        print state
        if (((rate + capacity) != 1600) or ((rate % 8) != 0)):
            return
        inputOffset = 0
        # === Absorb all the input blocks ===
        while(inputOffset < len(inputBytes)):
            blockSize = min(len(inputBytes)-inputOffset, rateInBytes)
            for i in range(blockSize):
                state[i] = state[i] ^ inputBytes[i+inputOffset]
            inputOffset = inputOffset + blockSize
            if (blockSize == rateInBytes):
                state = self.KeccakF1600(state)
                blockSize = 0
        # === Do the padding and switch to the squeezing phase ===
        state[blockSize] = state[blockSize] ^ delimitedSuffix
        if (((delimitedSuffix & 0x80) != 0) and (blockSize == (rateInBytes-1))):
            state = self.KeccakF1600(state)
        state[rateInBytes-1] = state[rateInBytes-1] ^ 0x80
        state = self.KeccakF1600(state)
        # === Squeeze out all the output blocks ===
        while(outputByteLen > 0):
            blockSize = min(outputByteLen, rateInBytes)
            outputBytes = outputBytes + state[0:blockSize]
            outputByteLen = outputByteLen - blockSize
            if (outputByteLen > 0):
                state = self.KeccakF1600(state)
        return binascii.hexlify(outputBytes).lower()
    
    def SHAKE128(self , inputBytes, outputByteLen):
        if outputBytes.isdigit() == False :
            raise ValueError("%s is not a number" %outputBytes)
        return self.Keccak(1344, 256, inputBytes, 0x1F, outputByteLen)

    def SHAKE256(self , inputBytes, outputByteLen):
        if outputBytes.isdigit() == False :
            raise ValueError("%s is not a number" %outputBytes)
        return self.Keccak(1088, 512, inputBytes, 0x1F, outputByteLen)

    def SHA3_224(self , inputBytes):
        return self.Keccak(1152, 448, inputBytes, 0x06, 224//8)

    def SHA3_256(self , inputBytes):
        return self.Keccak(1088, 512, inputBytes, 0x06, 256//8)

    def SHA3_384(self , inputBytes):
        return self.Keccak(832, 768, inputBytes, 0x06, 384//8)

    def SHA3_512(self , inputBytes):
        return self.Keccak(576, 1024, inputBytes, 0x06, 512//8)


class TreeHash(Keccak):
    def __init__(self):
        self.height = 3
        self.degree = 4
        self.base   = 1024
    
    def Treehash(self, hasher, inputBytes , *inputParams):
        
        def poolHash(hashString):
            if inputParams:
                outputBytes = inputParams[0]
                hashString = hasher(hashString , outputBytes)
            else:
                hashString = hasher(hashString)
            return hashString

        layer = self.height ** self.degree
        treeStructure = sum([self.degree ** height  for height in xrange(0, self.height+1)])
        currentIndex = treeStructure
        tree = [None for i in xrange(treeStructure)]

        for leaf in xrange(0, layer):
            tree[len(tree) - leaf - 1] = []

        group = len(inputBytes)/self.base + (len (inputBytes) % self.base != 0)

        for segment in xrange(0, group):
            tree[len(tree) - layer + segment % layer].append(inputBytes[segment * self.base : (segment + 1) * self.base])

        for floor in xrange(0, layer):
            currentBranch = ''.join(tree[len(tree) - floor - 1])
            tree[len(tree) - floor - 1] = currentBranch

        for currentLevel in range(self.height, -1, -1):
            currentNode = self.degree ** currentLevel
            currentIndex -= currentNode

            parallelPool = ProcessingPool(multiprocessing.cpu_count())
            for index in xrange(currentIndex, currentIndex + currentNode):
                if currentLevel < self.height:
                    tree[index] = []
                    for levelIndex in xrange(index * self.degree + 1, index * self.degree + (self.degree + 1) ):
                        tree[index].append(tree[levelIndex])
                    tree[index] = ''.join(tree[index]) 
                else:
                    if tree[index] != '':
                        tree[index] = "{0:0{1}x}".format(int(tree[index], 2), len(tree[index])/4)

            tree[currentIndex: currentIndex + currentNode] = parallelPool.map(poolHash, tree[currentIndex : currentIndex + currentNode])
        
        return tree[0]


    def SHAKE128_treehash(self , inputBytes, outputByteLen):
        if outputBytes.isdigit() == False :
            raise ValueError("%s is not a number" %outputBytes)
        return self.Treehash(super(TreeHash,self).SHAKE128, inputBytes , outputByteLen)

    def SHAKE256_treehash(self , inputBytes, outputByteLen):
        if outputBytes.isdigit() == False :
            raise ValueError("%s is not a number" %outputBytes)
        return self.Treehash(super(TreeHash,self).SHAKE256, inputBytes, outputByteLen)

    def SHA3_224_treehash(self , inputBytes):
        return self.Treehash(super(TreeHash,self).SHA3_224, inputBytes)

    def SHA3_256_treehash(self , inputBytes):
        return self.Treehash(super(TreeHash,self).SHA3_256, inputBytes)

    def SHA3_384_treehash(self , inputBytes):
        return self.Treehash(super(TreeHash,self).SHA3_256, inputBytes)

    def SHA3_512_treehash(self , inputBytes):
        return self.Treehash(super(TreeHash,self).SHA3_512, inputBytes)

    def setHeight(self, height):
        if height.isdigit() == False :
            raise ValueError("%s is not a number" %height)
        self.height =  height

    def setDegree(self, degree):
        if outputBytes.degree() == False :
            raise ValueError("%s is not a number" %degree)
        self.degree = degree

    def setBase(self, base):
        if base.isdigit() == False :
            raise ValueError("%s is not a number" %base)
        self.base = base


def bits(inputFile, message = False):
    if message:
        bytes = (ord(bits) for bits in inputFile)
    else:
        bytes = (ord(bits) for bits in inputFile.read())
    for bits in bytes:
        for bit in reversed(xrange(8)):
            yield (bits >> bit) & 1

def read_in_chunks(file_object, chunk_size=1048576):
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data

def hashed(input):
    return input

def getMessageFromFile(input):
    message = ''
    pool = Pool(multiprocessing.cpu_count())
    inputFile = open(input, 'r') 
    for piece in pool.imap(hashed , read_in_chunks(inputFile)):
        message += ''.join( map(str, [bit for bit in bits(piece, True)]))
    inputFile.close()
    pool.terminate()
    return message

def getMessageFromString(input):
    message = ''.join( map(str, [bit for bit in bits(input, message = True)]) )
    return message

def main():
    if sys.argv[1] == 'file':
        baseString = ''.join(map(str,getMessageFromFile(sys.argv[2])))
    else:
        baseString = ''.join(map(str,getMessageFromString(sys.argv[2])))

    message = baseString
    
    myKeccak = TreeHash()
    start =  time.time()
    print myKeccak.SHA3_512_treehash(message)
    print time.time() - start
    start = time.time()

    myKeccak = Keccak()
    message = myKeccak.makeSerialString(message)
    print myKeccak.SHA3_512(message)
    print time.time() - start


if __name__ == "__main__":
    main()



