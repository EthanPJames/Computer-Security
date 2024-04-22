import sys
from BitVector import *
from PrimeGenerator import * 
import math

class RSA():
    def __init__(self, e) ->None:
        self.e = e
        self.n = None
        self.d = None
        self.p = None
        self.q = None

#****************************************************************************************************************************************************************
    def generatepq(self, out1 :str, out2 :str) -> None: #Does the main define this correctly?????????????????????????????????????????????????????????????????????????????
        #Code adapted from AVI KAK PrimeGenerator.py
        #print("Here")
        gen = PrimeGenerator(bits = 128)
        while(1):
            p_value = gen.findPrime()
            q_value = gen.findPrime()
            MSB1 = p_value & 11 #Check MSB 128
            MSB2 = q_value & 11 #Check MSB 128
            #print("Prime returned p: %d" % p_value)
            if p_value != q_value and MSB1 == 1 and MSB2 == 1 and math.gcd(p_value-1, self.e) == 1 and  math.gcd(q_value-1, self.e) == 1:
                break
        FILEOUT1 = open(out1, "w")
        FILEOUT2 = open(out2, "w")
        FILEOUT1.write(str(p_value)) #Write P rand number to out file
        FILEOUT2.write(str(q_value)) #Write q rand number to out file
        # print(p_value)
        # print(q_value)
        return p_value, q_value

    
#*****************************************************************************************************************************************************************
    def encrypt ( self , plaintext :str , ciphertext :str ) -> None :
        #Convert file content to bitvector/open it 
        bv = BitVector(filename = plaintext)
        Fp_open = open(sys.argv[3], "r")
        p = int(Fp_open.read().strip())
        Fq_open = open(sys.argv[4], "r")
        q = int(Fq_open.read().strip())

        pq = p * q
        #print("PQ multiply: ", pq)
        FILEOUT = open(ciphertext, 'w') #Does it need to be wb
        while bv.more_to_read:
            #Read a block of 128 bits
            block = bv.read_bits_from_file(128)
            #print(len(block))

            #Do padding if required
            if(block.length()!=128):
                block.pad_from_right(128-block.length())
            block.pad_from_left(128) #Prepend with 128 bits

            #encryption modulus
            modulus = pow(int(block), self.e, pq)
            bv_output = BitVector(intVal = modulus, size =256) #Convert modulus to bitvec so we can output in hex
            #print(bv_output.get_bitvector_in_hex())
            output_hex = bv_output.get_bitvector_in_hex()
            FILEOUT.write(output_hex)
        FILEOUT.close()

#*****************************************************************************************************************************************************************
    def decrypt ( self , ciphertext :str , recovered_plaintext :str ) -> None :
        #Do all preliminary file openings
        innput = (open(ciphertext, "r")).read() #Read the input
        Fp_open = open(sys.argv[3], "r") #Open P value
        #Open output file
        output = open(recovered_plaintext, "w")
        
        p = int(Fp_open.read()) #Get Pval
        #print(p)
        Fq_open = open(sys.argv[4], "r")
        q = int(Fq_open.read()) #Get QVal

        pq = p*q #modulus value
        totient = (p - 1) * (q - 1) #Calculate the totient
        
        #must convert values to bit vector to use MI function
        bv_e = BitVector(intVal=self.e) #convert E to bitvector
        bv_pq = BitVector(intVal=pq) #Convert modulus to bitvector
        bv_p = BitVector(intVal=p) #Convert to p to bitvector
        bv_q = BitVector(intVal=q) #Convert q to bitvector
        bv_totient = BitVector(intVal=totient) #Totient to bitvector
        bv_d = bv_e.multiplicative_inverse(bv_totient).int_val() #Calcs d value
        bv_xp = q * bv_q.multiplicative_inverse(bv_p).int_val() #calc xp value
        bv_xq = p * bv_p.multiplicative_inverse(bv_q).int_val() #calc xq value
        
        bv_file =BitVector(hexstring = innput)
        # #Beign actual decrypting
        for i in range((len(bv_file) // 256)):
            #print(innput[i*256: (i + 1)*256])
            block = bv_file[i*256: (i + 1)*256].int_val()#BitVector(hexstring=innput[i*256: (i + 1)*256]) #Get ciphertext as an integer
            #Execute CRT
            Vp = pow(block, bv_d, p)
            Vq = pow(block, bv_d, q)
            decrypted_block = (Vp*bv_xp + Vq*bv_xq) % pq
            #Convert to bitvector
            bv_decrypt = BitVector(intVal = decrypted_block, size = 256)
            #print(bv_decrypt.get_bitvector_in_hex())
            bv_decrypt = bv_decrypt[128: 256]
            #print("After: ", bv_decrypt.get_bitvector_in_hex())
            output.write(bv_decrypt.get_bitvector_in_ascii())
#******************************************************************************************************************************************************************
if __name__ == '__main__':
    cipher = RSA(e=65537)
    if sys.argv[1] == '-e':
        cipher.encrypt(plaintext = sys.argv[2], ciphertext = sys.argv[5])
    elif sys.argv[1] == '-d':
        cipher.decrypt (ciphertext = sys.argv[2],recovered_plaintext =sys.argv[5])
    elif sys.argv [1] == "-g":
         cipher.generatepq(out1 = sys.argv[2], out2 = sys.argv[3])
#******************************************************************************************************************************************************************


    