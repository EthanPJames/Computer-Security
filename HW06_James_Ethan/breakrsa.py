import sys
from BitVector import *
from PrimeGenerator import * 
from solve_pRoot import *
import math


class breakRSA():
    def __init__(self, e) -> None:
        self.e = e #e = 3
        self.e_bv = BitVector(intVal = self.e) #Convert e to bitvector
#********************************************************************************************************************************************************************
    def generatepq(self) -> None: #Does the main define this correctly?????????????????????????????????????????????????????????????????????????????
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
        return p_value, q_value
#********************************************************************************************************************************************************************

#********************************************************************************************************************************************************************
    def encrypt_caller(self, message: str, enc1: str, enc2: str, enc3: str, moduli_out: str) -> None:
        #Open the output file
        output1 = open(enc1, "w")  
        output2 = open(enc2, "w")
        output3 = open(enc3, "w")      
        output4 = open(moduli_out, "w")
        
        #Call number one for first encrypted public key
        p_val1, q_val1 = self.generatepq()
        modulus1 = p_val1 *q_val1
        totient1 = (p_val1 - 1)*(q_val1-1)
        bv_totient1 = BitVector(intVal=totient1)
        d1 = self.e_bv.multiplicative_inverse(bv_totient1).int_val()
        #Call actual encrypting fucntion here
        self.encrypting_RSA(message, output1,p_val1,q_val1)

        #Call number two for second encrypted public key
        p_val2, q_val2 = self.generatepq()
        modulus2 = p_val2 *q_val2
        totient2 = (p_val2 - 1)*(q_val2-1)
        bv_totient2 = BitVector(intVal=totient2)
        d2 = self.e_bv.multiplicative_inverse(bv_totient2).int_val()
        self.encrypting_RSA(message, output2,p_val2,q_val2)

        #Call number three for third encryption public key
        p_val3, q_val3 = self.generatepq()
        modulus3 = p_val3 *q_val3
        totient3 = (p_val3 - 1)*(q_val3-1)
        bv_totient3 = BitVector(intVal=totient3)
        d3 = self.e_bv.multiplicative_inverse(bv_totient3).int_val()
        self.encrypting_RSA(message, output3,p_val3,q_val3)

        print(modulus1)
        print(modulus2)
        print(modulus3)
        #Write the modulus to an ouptut file
        output4.write(str(modulus1) + '\n')
        output4.write(str(modulus2) + '\n')
        output4.write(str(modulus3))
#********************************************************************************************************************************************************************
    def encrypting_RSA(self, plaintext: str, out, p, q,) -> None:
        bv = BitVector(filename = plaintext)
        pq = p * q
        #print("PQ multiply: ", pq)
        while bv.more_to_read:
            #Read a block of 128 bits
            block = bv.read_bits_from_file(128)
            #print(len(block))

            #Do padding if required
            if(block.length()!=128):
                block.pad_from_right(128-block.length())
            #block.pad_from_left(128) #Prepend with 128 bits

            #encryption modulus
            modulus = pow(int(block), self.e, pq)
            bv_output = BitVector(intVal = modulus, size =256) #Convert modulus to bitvec so we can output in hex
            #print(bv_output.get_bitvector_in_hex())
            output_hex = bv_output.get_bitvector_in_hex()
            out.write(output_hex)
        out.close()
#********************************************************************************************************************************************************************
            
#*******************************************************************************************************************************************************************
    def cracked(self, enc1: str, enc2: str, enc3:str, moduli_out:str, cracked_out:str) -> None:
            #Read the three moduli, do they need to be ints
            open_moduli = open(moduli_out, "r")
            m_line1 = int(open_moduli.readline())
            m_line2 = int(open_moduli.readline())
            m_line3 = int(open_moduli.readline())

            #Convert moduli in each function to bitvector to use as part of multiplicative inverse
            bv_modulus1 = BitVector(intVal=m_line1)
            bv_modulus2 = BitVector(intVal=m_line2)
            bv_modulus3 = BitVector(intVal=m_line3)

            #Read files as hexstring containing the encrypted code
            in1 = open(enc1, "r").read().strip()
            in2 = open(enc2, "r").read().strip()
            in3 = open(enc3, "r").read().strip()
            bv_1_hex = BitVector(hexstring = in1)
            bv_2_hex = BitVector(hexstring = in2)
            bv_3_hex = BitVector(hexstring = in3)

            #Get overall modulsu
            moduli_combined = m_line1 * m_line2 *m_line3 

            #Modified code
            #Mod 1
            m1_bv = BitVector(intVal = (m_line2*m_line3)) #Help from TA
            m1_inv = m1_bv.multiplicative_inverse(bv_modulus1)
            m1_int = int(m1_inv)
            #Mod 2
            m2_bv = BitVector(intVal = (m_line1*m_line3)) #Help from TA
            m2_inv = m2_bv.multiplicative_inverse(bv_modulus2)
            m2_int = int(m2_inv)
            #Mod 3
            m3_bv = BitVector(intVal = (m_line1*m_line2)) #Help from TA
            m3_inv = m3_bv.multiplicative_inverse(bv_modulus3)
            m3_int = int(m3_inv)
            

            
            output = open(cracked_out, "w")
            n = 0
            #Want to run while loop as long as there is stuff in all files
            for i in range(len(bv_1_hex)//256):
                #Read bits and convert to integer 
                cipher_1 = bv_1_hex[256*i:(i+1)*256] #Read 256 from enc1
                cipher1_int = cipher_1.int_val() #Convert cipher to an integer value
                cipher_2 = bv_2_hex[256*i:(i+1)*256] #Read 256 from enc2
                cipher2_int = cipher_2.int_val() #Convert cipher to an integer value
                cipher_3 = bv_3_hex[256*i:(i+1)*256] #Read 256 from enc2
                cipher3_int = cipher_3.int_val() #Convert cipher to an integer value

                #Now do chinese remainder theorum, %TA TOLD ME TO WRRITE THIS, GOT MATH FROM TA
                #N^-1 * n2n3 * ciphertext
                theorum = ((m1_int * int(m1_bv) * (cipher1_int)) + (m2_int * int(m2_bv) * (cipher2_int)) + (m3_int * int(m3_bv) * (cipher3_int))) % moduli_combined

                #Does the cubed root
                cube_root = solve_pRoot(3,theorum) 
                #Convert to bitvector to be able to write in ascii
                convert_pt = BitVector(intVal = cube_root, size=256)
                _, out = convert_pt.divide_into_two()
                output.write(out.get_bitvector_in_ascii())
                n += 1
#********************************************************************************************************************************************************************
if __name__ == '__main__':
    cipher = breakRSA(e=3)
    if sys.argv[1] == '-e':
        cipher.encrypt_caller(message = sys.argv[2], enc1 = sys.argv[3], enc2 = sys.argv[4], enc3 = sys.argv[5], moduli_out = sys.argv[6])
    elif sys.argv[1] == '-c':
        cipher.cracked (enc1 = sys.argv[2], enc2 = sys.argv[3], enc3 = sys.argv[4], moduli_out = sys.argv[5], cracked_out = sys.argv[6])
  