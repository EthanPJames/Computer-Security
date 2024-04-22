import sys
from BitVector import *
#*CODE ADAPTED FROM AVI KAK SHA256.py
class sha512():
    def __init__(self, plaintext: str) ->None:
        #Open input file
        in1 = open(plaintext, "r").read()
        self.bv_input = BitVector(textstring = in1)
        #Initialization vectors
        self.h0 = BitVector(hexstring = '6a09e667f3bcc908')
        self.h1 = BitVector(hexstring = 'bb67ae8584caa73b')
        self.h2 = BitVector(hexstring = '3c6ef372fe94f82b')
        self.h3 = BitVector(hexstring = 'a54ff53a5f1d36f1')
        self.h4 = BitVector(hexstring = '510e527fade682d1')
        self.h5 = BitVector(hexstring = '9b05688c2b3e6c1f')
        self.h6 = BitVector(hexstring = '1f83d9abfb41bd6b')
        self.h7 = BitVector(hexstring = '5be0cd19137e2179')

        #Round Constants
        self.k = ['428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc',
                    '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118',
                    'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2',
                    '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694',
                    'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65',
                    '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5',
                    '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4',
                    'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70',
                    '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df',
                    '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
                    'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30',
                    'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8',
                    '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8',
                    '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3',
                    '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec',
                    '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b',
                    'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178',
                    '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b',
                    '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c',
                    '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817']
        self.K_bv = [BitVector(hexstring = k_constant) for k_constant in self.k]
        
        #Step 1 of hashing algorithm - Pad the input message - ADAPTED AVI KAK CODE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        self.length = self.bv_input.length() #Get size of input files
        self.bv1 = self.bv_input + BitVector(bitstring="1") #Account for zeros
        self.length1 = self.bv1.length()
        self.howmanyzeros = (896 - self.length1) % 1024
        self.zerolist = [0] * self.howmanyzeros
        self.bv2 = self.bv1 + BitVector(bitlist = self.zerolist)
        self.bv3 = BitVector(intVal = self.length, size = 128) #Should this be 128 bits?????????
        self.bv4 = self.bv2 + self.bv3


        #Intialzie array of words
        self.words = [None] * 80
        





#***************************************************************************************************************************************************************
    def hashing1(self, out) -> None:
        #Open the output file
        #out_open = open(out, "w") #Open the output file
        #STEP 2 OF THE HASHING ALGORITHM: Now we need to create a message schedule!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        for n in range(0,self.bv4.length(),1024):
            block = self.bv4[n:n+1024]
            self.words[0:16] = [block[i:i+64] for i in range(0,1024,64)] #First 16 words that are 64bits

            for i in range(16, 80):
                i_minus_2_word = self.words[i-2]
                i_minus_15_word = self.words[i-15]

                sigma0 = (i_minus_15_word.deep_copy() >> 1) ^ (i_minus_15_word.deep_copy() >> 8) ^ \
                                                             (i_minus_15_word.deep_copy().shift_right(7))
                sigma1 = (i_minus_2_word.deep_copy() >> 19) ^ (i_minus_2_word.deep_copy() >> 61) ^ \
                                                             (i_minus_2_word.deep_copy().shift_right(6))
                self.words[i] = BitVector(intVal=(int(self.words[i-16]) + int(sigma1) + int(self.words[i-7]) + \
                                                                      int(sigma0)) & 0xFFFFFFFFFFFFFFFF, size=64)
            #  Before we can start STEP 3, we need to store the hash buffer contents obtained from the 
            #  previous input message block in the variables a,b,c,d,e,f,g,h:
            a,b,c,d,e,f,g,h = self.h0,self.h1,self.h2,self.h3,self.h4,self.h5,self.h6,self.h7
            #Step 3 carrying out round based processing !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            for i in range(80):
                ch = (e & f) ^ ((~e) & g)
                maj = (a & b) ^ (a & c) ^ (b & c)
                sum_a = ((a.deep_copy()) >> 28) ^ ((a.deep_copy()) >> 34) ^ ((a.deep_copy()) >> 39)
                sum_e = ((e.deep_copy()) >> 14) ^ ((e.deep_copy()) >> 18) ^ ((e.deep_copy()) >> 41)
                t1 = BitVector(intVal=(int(h) + int(ch) + int(sum_e) + int(self.words[i]) + int(self.K_bv[i])) & \
                                                                                     0xFFFFFFFFFFFFFFFF, size=64)
                t2 = BitVector(intVal=(int(sum_a) + int(maj)) & 0xFFFFFFFFFFFFFFFF, size=64)
                h = g
                g = f
                f = e
                e = BitVector(intVal=(int(d) + int(t1)) & 0xFFFFFFFFFFFFFFFF, size=64)
                d = c
                c = b
                b = a
                a = BitVector(intVal=(int(t1) + int(t2)) & 0xFFFFFFFFFFFFFFFF, size=64)
            
            #  STEP 4 OF THE HASHING ALGORITHM:  The values in the temporary variables a,b,c,d,e,f,g,h !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            #                                    AFTER 80 rounds of processing are now mixed with the 
            #                                    contents of the hash buffer as calculated for the 
            #                                    previous block of the input message:
            self.h0 = BitVector( intVal = (int(self.h0) + int(a)) & 0xFFFFFFFFFFFFFFFF, size=64 )
            self.h1 = BitVector( intVal = (int(self.h1) + int(b)) & 0xFFFFFFFFFFFFFFFF, size=64 )
            self.h2 = BitVector( intVal = (int(self.h2) + int(c)) & 0xFFFFFFFFFFFFFFFF, size=64 )
            self.h3 = BitVector( intVal = (int(self.h3) + int(d)) & 0xFFFFFFFFFFFFFFFF, size=64 )
            self.h4 = BitVector( intVal = (int(self.h4) + int(e)) & 0xFFFFFFFFFFFFFFFF, size=64 )
            self.h5 = BitVector( intVal = (int(self.h5) + int(f)) & 0xFFFFFFFFFFFFFFFF, size=64 )
            self.h6 = BitVector( intVal = (int(self.h6) + int(g)) & 0xFFFFFFFFFFFFFFFF, size=64 )
            self.h7 = BitVector( intVal = (int(self.h7) + int(h)) & 0xFFFFFFFFFFFFFFFF, size=64 )

            #  Concatenate the contents of the hash buffer to obtain a element BitVector object:
            message_hash = self.h0 + self.h1 + self.h2 + self.h3 + self.h4 + self.h5 + self.h6 + self.h7

            #  Get the hex representation of the binary hash value:
            hash_hex_string = message_hash.getHexStringFromBitVector()
        with open(out, 'w') as file_point:
            file_point.write(hash_hex_string)

        





#*********************************************************************************************************************************************************************
if __name__ == "__main__":
    hashing = sha512(plaintext = sys.argv[1])
    hashing.hashing1(sys.argv[2])
        