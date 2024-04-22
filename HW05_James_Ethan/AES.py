import sys
from BitVector import *

class AES:
    # class constructor - when creating an AES object , the
    # class ’s constructor is executed and instance variables
    # are initialized
    def __init__ ( self , keyfile :str ) -> None :
        self.AES_modulus = BitVector(bitstring = '100011011') #Modulus used in other functions, from lecture code
        self.key = keyfile     
        self.bv_key = BitVector(filename = self.key) #Get the key as a bit vector
        self.read_key = self.bv_key.read_bits_from_file(256) #Raead the keys
        self.words = self.gen_key_schedule_256(self.read_key) #Generate the words which is already put into a list from lecture code
        num_rounds = 14
        self.round_keys = [None for i in range(num_rounds+1)]
        self.subBytesTable = []       #Does this need to be global????????????????????                                           # for encryption
        self.invSubBytesTable = []
        self.genTables()
        for i in range(num_rounds+1):
            self.round_keys[i] = (self.words[i*4] + self.words[i*4+1] + self.words[i*4+2] +self.words[i*4+3])
            
        
#******************************************************************************************************************************************************************************
        #CODE TAKEN FROM AVI KAK LECTURES
    def gen_key_schedule_256(self, key_bv):
        byte_sub_table = self.gen_subbytes_table() #Is this executing correctly??????????????????????????????????????????????????????????????
        #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
        #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
        #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
        #  schedule. We will store all 60 keywords in the following list:
        key_words = [None for i in range(60)]
        round_constant = BitVector(intVal = 0x01, size=8)
        for i in range(8):
            key_words[i] = key_bv[i*32 : i*32 + 32]
        for i in range(8,60):
            if i%8 == 0:
                kwd, round_constant = self.gee(key_words[i-1], round_constant, byte_sub_table) #is this executing correctly??????????????????????????????
                key_words[i] = key_words[i-8] ^ kwd
            elif (i - (i//8)*8) < 4:
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            elif (i - (i//8)*8) == 4:
                key_words[i] = BitVector(size = 0)
                for j in range(4):
                    key_words[i] += BitVector(intVal = 
                                    byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
                key_words[i] ^= key_words[i-8] 
            elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words
    
    def gee(self, keyword, round_constant, byte_sub_table):
        '''
        This is the g() function you see in Figure 4 of Lecture 8.
        '''
        AES_mod = BitVector(bitstring='100011011')
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size = 0)
        for i in range(4):
            newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_mod, 8) #How do I call this?
        return newword, round_constant
    
    def gen_subbytes_table(self):
        AES_mod = BitVector(bitstring='100011011') #I added this from lecture notes!!!!!!!!!!!!!!!!!!!!!!!, Did it somehwere else also!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        subBytesTable = []
        c = BitVector(bitstring='01100011')
        for i in range(0, 256):
            a = BitVector(intVal = i, size=8).gf_MI(AES_mod, 8) if i != 0 else BitVector(intVal=0)
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            subBytesTable.append(int(a))
        return subBytesTable
#******************************************************************************************************************************************************************************
    def encrypt ( self , plaintext :str , ciphertext :str ) -> None :
        output = open(ciphertext, 'w') #Open output file
        bv = BitVector(filename = plaintext) #Convert plaintext to a bit vector and use like that
        
        while(bv.more_to_read):
            block = bv.read_bits_from_file(128)
            #Execute Padding
            if(block.length()!=128):
                block.pad_from_right(128-block.length())
            #Build state array
           
            statearray = self.popState_array(block)
            #Does the initial xoring
            statearray = self.XORroundkey(statearray, 0) #TA HELP
            #Begin the actual encryption rounds
            for round_num in range (1,15):
                #Sub Bytes
                statearray = self.subbytes(statearray)
                #Shift Rows
                statearray = self.shiftrows(statearray)
                #Check if we have to do Mix columns
                if(round_num !=14): #Run this if we are not at the end
                    statearray = self.mixcolumns(statearray)
                #Xor round key
                statearray = self.XORroundkey(statearray,  round_num) #TA HELP, if we are at the end call the XOR function which TA helped me createa
            
            final_bv = BitVector(size = 0)
            #Flatten out and print
            for i in range(4):
                for j in range(4):
                    final_bv = final_bv + statearray[j][i]
            output.write(final_bv.get_bitvector_in_hex())              
#*******************************************************************************************************************************************************************
    def subbytes(self, state_array):
        # subtable = self.gen_subbytes_table()
        for row in range(4):
            for column in range(4):
                state_array[row][column] = BitVector(intVal=self.subBytesTable[state_array[row][column].intValue()], size=8) #might need to be 0, TA HELPED WITH THIS
        return state_array
        # subBytesTable = self.gen_subbytes_table()  # Get the substitution table
        # for i in range(4):
        #     for j in range(4):
        #         ind = state_array[i][j].intValue()  # Extract integer value from BitVector
        #         state_array[i][j] = BitVector(intVal=subBytesTable[ind], size=8)  # Substitute and assign as BitVector
        # return state_array 


#**********************************************************************************************************************************************************************
    #Does this overwrite itself????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
    def shiftrows(self, stateArr): #NEVER CHANGED
        #Taken from matrix in lecture code
        newArr = [[stateArr[0][0], stateArr[0][1], stateArr[0][2], stateArr[0][3]],
              [stateArr[1][1], stateArr[1][2], stateArr[1][3], stateArr[1][0]],
              [stateArr[2][2], stateArr[2][3], stateArr[2][0], stateArr[2][1]],
              [stateArr[3][3], stateArr[3][0], stateArr[3][1], stateArr[3][2]]]
        return newArr
#*****************************************************************************************************************************************************************
    #THIS FUNCTION MIGHT BE WRONG NOT GONNA LIE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!,SHould be correct though
    def mixcolumns(self, state_array_post_post): #NEVER CHNAGED
        hex2 = BitVector(bitstring = "00000010")
        hex3 = BitVector(bitstring = "00000011")

        AES_mod = BitVector(bitstring='100011011')
        mix_col_state = [[0 for x in range(4)] for x in range(4)]
        #Changed it to add if statements so that we acn see what do operations based on which row we are in
        for i in range(4):
            for j in range(4):
                #print(state_array_post_post[i][j])
                if(i == 0): #If in first row
                    mix_col_state[i][j] = (state_array_post_post[0][j].gf_multiply_modular(hex2, AES_mod, 8)) ^ (state_array_post_post[1][j].gf_multiply_modular(hex3, AES_mod, 8)) ^ (state_array_post_post[2][j]) ^ (state_array_post_post[3][j])
                elif(i == 1): #if in second row
                    mix_col_state[i][j] = (state_array_post_post[1][j].gf_multiply_modular(hex2, AES_mod, 8)) ^ (state_array_post_post[2][j].gf_multiply_modular(hex3, AES_mod, 8)) ^ (state_array_post_post[0][j]) ^ (state_array_post_post[3][j])
                elif(i == 2): #if in thrid row
                    mix_col_state[i][j] = (state_array_post_post[2][j].gf_multiply_modular(hex2, AES_mod, 8)) ^ (state_array_post_post[3][j].gf_multiply_modular(hex3, AES_mod, 8)) ^ (state_array_post_post[1][j]) ^ (state_array_post_post[0][j])
                else: #if in forth row
                    mix_col_state[i][j] = (state_array_post_post[3][j].gf_multiply_modular(hex2, AES_mod, 8)) ^ (state_array_post_post[0][j].gf_multiply_modular(hex3, AES_mod, 8)) ^ (state_array_post_post[1][j]) ^ (state_array_post_post[2][j])

        return(mix_col_state)
#************************************************************************************************************************************************************************************************************************
    # def XORroundkey(self, statearray, words, round_num):
    def XORroundkey(self, statearray, round_num):
        new_sa = BitVector(size = 0)
        for i in range(4):
            for j in range(4):
                new_sa = new_sa + statearray[j][i]
        
        new_sa = new_sa ^ self.round_keys[round_num]
        return(self.popState_array(new_sa))
        # new_state = [[0 for x in range(4)] for x in range(4)] #Createa temp state array to store xor value in
        # for i in range(4):
        #     for j in range(4):
        #         #Is this the correct formula, since I cannot just straight up Xor????????????????????????????????????????????????????????????????
        #         #Xor with the words created which neds [value*4+i][j*8:j*8+8] This allows it access correct positions since its stored as bytes
        #         new_state[j][i] = statearray[j][i] ^ words[round_num * 4+i][j*8:j*8+8] #TA HELPed with this since XOring round keys was failing initially
        # return new_state
#************************************************************************************************************************************************************************************************************************
    # def blockFromStateArr(self, stateArr):
    #     # this function generate a 128 bit block from a state arr
    #     bitVec = BitVector(size=0)
    #     for column in range(4):
    #         for row in range(4):
    #             bitVec += stateArr[row][column]
    #     return bitVec
#************************************************************************************************************************************************************************************************************************
    # def generateStateArray(self, bitVec):
    #     # generates State array form a bit vector
    #     stateArr = [[None for _ in range(4)] for _ in range(4)]
    #     for column in range(0, 4):
    #         for row in range(0, 4):
    #             byteNum = column * 4 + row
    #             stateArr[row][column] = bitVec[byteNum * 8: (byteNum + 1) * 8]
    #     return stateArr
#*********************************************************************************************************************************************************************************
    def convert(self, state_array):
        new_sa = BitVector(size = 0)
        for i in range(4):
            for j in range(4):
                new_sa = new_sa + state_array[j][i]
            #print("value is 14")
        return(new_sa)
#*************************************************************************************************************************************************************************
#**********************************************************************************************************************************************************************
    def genTables(self):
        # self.subBytesTable = []       #Does this need to be global????????????????????                                           # for encryption
        # self.invSubBytesTable = []
        AES_modulus = BitVector(bitstring='100011011')
        c = BitVector(bitstring='01100011')
        d = BitVector(bitstring='00000101')
        for i in range(0, 256):
            # For the encryption SBox
            a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            # For bit scrambling for the encryption SBox entries:
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            self.subBytesTable.append(int(a))
            # For the decryption Sbox:
            b = BitVector(intVal = i, size=8)
            # For bit scrambling for the decryption SBox entries:
            b1,b2,b3 = [b.deep_copy() for x in range(3)]
            b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
            check = b.gf_MI(AES_modulus, 8)
            b = check if isinstance(check, BitVector) else 0
            self.invSubBytesTable.append(int(b))
#**************************************************************************************************************************************************************************
#DECRYPT PORTION
#***********************************************************************************************************************************************************************************************************
    def decrypt ( self , ciphertext :str , decrypted :str ) -> None :
        FILEOUT_decrypt = open(decrypted, 'w')  # Open the output file for writing
        innput = (open(ciphertext, "r")).read() #Read the input
        
        for i in range(int(len(innput)/32)):
            #Create it as a bitvector
            bitvec = BitVector(hexstring = innput[i*32:i*32+32]) #Chunk it
            #print("Read in: ", bitvec.get_bitvector_in_hex())
            if bitvec._getsize() > 0:
                    #Populate the state array
                    statearray = self.popState_array(bitvec)
                    #Intial Xoring
                    statearray = self.XORroundkey(statearray,  14) #XOR with the last set of words 
                    #print(statearray)
                    #Start my decrytion
                    for value in range(13, -1, -1):
                        #print(value)
                        statearray = self.inverse_shift_rows(statearray) #CALL INVERSE SHIFT ROWS FUNCTION  
                        # for d in range(2):
                        #     for f in range(2):
                        #         print(statearray[f][d].get_bitvector_in_hex())
                        # break
                        
                        statearray = self.inverse_substitute_bytes(statearray) #CALl inverse sub bytes
                        
                        statearray = self.XORroundkey(statearray,  value)
                        
                        if(value != 0):#We want to do mix columns
                            statearray = self.inverse_mix_columns(statearray)
                    # break
                    #Flatten out and output
                    decrypted = BitVector(size = 0)
                    for i in range(4):
                        for j in range(4):
                            # print(statearray[j][i])
                            decrypted = decrypted + statearray[j][i]
                    #print(decrypted.get_bitvector_in_ascii())
                    FILEOUT_decrypt.write(decrypted.get_bitvector_in_ascii())

     
        
#*******************************************************************************************************************************************************************
    def inverse_mix_columns(self, state_array_post_post):
       
        # AES_mod = BitVector(bitstring='100011011')
        # mix_col_state = [[0 for x in range(4)] for x in range(4)]
        hexE = BitVector(hexstring='0e') 
        hexB = BitVector(hexstring='0b')
        hexD = BitVector(hexstring='0d')
        hex9 = BitVector(hexstring='09')
        # #MIGHT BE WRONG!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        # for i in range(4):
        #     for j in range(4):
        #         #print(state_array_post_post[i][j])
        #         if(j == 0):
        #             mix_col_state[i][j] = (state_array_post_post[0][j].gf_multiply_modular(hexE, AES_mod, 8)) ^ (state_array_post_post[1][j].gf_multiply_modular(hexB, AES_mod, 8)) ^ (state_array_post_post[2][j].gf_multiply_modular(hexD, AES_mod, 8)) ^ (state_array_post_post[3][j].gf_multiply_modular(hex9, AES_mod, 8))
        #         elif(j == 1):
        #             mix_col_state[i][j] = (state_array_post_post[1][j].gf_multiply_modular(hex9, AES_mod, 8)) ^ (state_array_post_post[2][j].gf_multiply_modular(hexE, AES_mod, 8)) ^ (state_array_post_post[0][j].gf_multiply_modular(hexB, AES_mod, 8)) ^ (state_array_post_post[3][j].gf_multiply_modular(hexD, AES_mod, 8))
        #         elif(j == 2):
        #             mix_col_state[i][j] = (state_array_post_post[2][j].gf_multiply_modular(hexD, AES_mod, 8)) ^ (state_array_post_post[3][j].gf_multiply_modular(hex9, AES_mod, 8)) ^ (state_array_post_post[1][j].gf_multiply_modular(hexE, AES_mod, 8)) ^ (state_array_post_post[0][j].gf_multiply_modular(hexB, AES_mod, 8))
        #         else:
        #             mix_col_state[i][j] = (state_array_post_post[3][j].gf_multiply_modular(hexB, AES_mod, 8)) ^ (state_array_post_post[0][j].gf_multiply_modular(hexD, AES_mod, 8)) ^ (state_array_post_post[1][j].gf_multiply_modular(hex9, AES_mod, 8)) ^ (state_array_post_post[2][j].gf_multiply_modular(hexE, AES_mod, 8))
            
        # return(mix_col_state)
        #Adapted from avi cac lectures notes
        inv_mic_col = [[None for _ in range(4)] for _ in range(4)]
        
        modulus = BitVector(bitstring='100011011')
        for column in range(4):
            # first row
            inv_mic_col[0][column] = hexE.gf_multiply_modular(state_array_post_post[0][column], modulus, 8)
            inv_mic_col[0][column] ^= hexB.gf_multiply_modular(state_array_post_post[1][column], modulus, 8)
            inv_mic_col[0][column] ^= hexD.gf_multiply_modular(state_array_post_post[2][column], modulus, 8)
            inv_mic_col[0][column] ^= hex9.gf_multiply_modular(state_array_post_post[3][column], modulus, 8)
            # second row
            inv_mic_col[1][column] = hex9.gf_multiply_modular(state_array_post_post[0][column], modulus, 8)
            inv_mic_col[1][column] ^= hexE.gf_multiply_modular(state_array_post_post[1][column], modulus, 8)
            inv_mic_col[1][column] ^= hexB.gf_multiply_modular(state_array_post_post[2][column], modulus, 8)
            inv_mic_col[1][column] ^= hexD.gf_multiply_modular(state_array_post_post[3][column], modulus, 8)
            # third row
            inv_mic_col[2][column] = hexD.gf_multiply_modular(state_array_post_post[0][column], modulus, 8)
            inv_mic_col[2][column] ^= hex9.gf_multiply_modular(state_array_post_post[1][column], modulus, 8)
            inv_mic_col[2][column] ^= hexE.gf_multiply_modular(state_array_post_post[2][column], modulus, 8)
            inv_mic_col[2][column] ^= hexB.gf_multiply_modular(state_array_post_post[3][column], modulus, 8)
            # forth row
            inv_mic_col[3][column] = hexB.gf_multiply_modular(state_array_post_post[0][column], modulus, 8)
            inv_mic_col[3][column] ^= hexD.gf_multiply_modular(state_array_post_post[1][column], modulus, 8)
            inv_mic_col[3][column] ^= hex9.gf_multiply_modular(state_array_post_post[2][column], modulus, 8)
            inv_mic_col[3][column] ^= hexE.gf_multiply_modular(state_array_post_post[3][column], modulus, 8)
        return inv_mic_col

        

#********************************************************************************************************************************************************************
    #ADAPTED FROM AVI KAK LECTURE SLIDES         
    def inverse_shift_rows(self, state_array_post):
        newArr = [[state_array_post[0][0], state_array_post[0][1], state_array_post[0][2], state_array_post[0][3]],
              [state_array_post[1][3], state_array_post[1][0], state_array_post[1][1], state_array_post[1][2]],
              [state_array_post[2][2], state_array_post[2][3], state_array_post[2][0], state_array_post[2][1]],
              [state_array_post[3][1], state_array_post[3][2], state_array_post[3][3], state_array_post[3][0]]]
        return newArr
        
#***********************************************************************************************************************************************************************
    def inverse_substitute_bytes(self, state_array):
        # subtable = self.gen_subbytes_table()
        for row in range(4):
            for column in range(4):
                state_array[row][column] = BitVector(intVal=self.invSubBytesTable[state_array[row][column].intValue()], size=8) #might need to be 0, TA HELPED WITH THIS
        return state_array 
#*************************************************************************************************************************************************************************
    def popState_array(self, block):
        statearray = [[BitVector(size=8) for x in range(4)]for x in range(4)] #From lecture code, create it as a bitvector
        for i in range(4):
            for j in range(4):
                statearray[j][i] = block[32*i+8*j:32*i+8*j+8] #[32*i + 8*j: 32*i + 8*(j+1)]#[32*i+8*j:32*i+8*j+8] #From AVI KAK lecture code
        return(statearray)
#*******************************************************************************************************************************************************************************
#IMAGE PORTION HW 5
#*******************************************************************************************************************************************************************************
    def ctr_aes_image ( self , iv , image_file , enc_image ):
        ##Open file and read first three lines
        file_point = open(image_file, 'rb')
        l1 = file_point.readline()
        #print(len(l1))
        l2 = file_point.readline()
        #print(len(l2))
        l3 = file_point.readline()
        #print(len(l3))
        image_datas = BitVector(filename=image_file)
        #Immediately write the header to the output file
        out = open(enc_image, 'wb')
        out.write(l1)
        out.write(l2)
        out.write(l3)

        #file_read = file_point.read() #Reads entire file
        #print(type(file_read))
        #bv_file = BitVector(rawbytes = file_read) #Should it be rawbytes or bitstring
        
        #length = len(bv_file) #Lenght of file
        #print("Length of file:", length)
        #print("Are we getting to the for loop")
        ##for i in range(0, length //128):
            #print(i)
            #Read the block
            #block = bv_file[i*128:128*(i+1)]
            #Execute Padding
        image_datas.read_bits_from_file(112)
        while image_datas.more_to_read:
            block = image_datas.read_bits_from_file(128)
            #print("HEX rep: ", block.get_bitvector_in_hex())
            if(block.length()!=128):
                block.pad_from_right(128-block.length())
            #bit_val = BitVector(intVal = (1 + int(iv)), size =128)
            #Do encrytion on the block
            encrypt_block = self.encryption_image(iv)
            #Do xoring with plaintext step here
            ciphertext_xoring = encrypt_block ^ block 
            # print("HEX rep: ", ciphertext_xoring.get_bitvector_in_hex())
            #Write the block to the output file 
            ciphertext_xoring.write_to_file(out)
            #Convert the intitalization vector to an int for incrementing
            iv = BitVector(intVal= iv.int_val() + 1, size = 128)
            #Do i need to convert back to Bit vector??????????? or is it ok like this??????????????????????????????????????????????????????????????????????????
           
#????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
    def encryption_image ( self , bv) -> None :
            
            
            statearray = self.popState_array(bv)
            #print("Do we get past createing state array")
            #Does the initial xoring
            statearray = self.XORroundkey(statearray, 0) #TA HELP
            #Begin the actual encryption rounds
            for round_num in range (1,15):
                #Sub Bytes
                statearray = self.subbytes(statearray)
                #Shift Rows
                statearray = self.shiftrows(statearray)
                #Check if we have to do Mix columns
                if(round_num !=14): #Run this if we are not at the end
                    statearray = self.mixcolumns(statearray)
                #Xor round key
                statearray = self.XORroundkey(statearray,  round_num) #TA HELP, if we are at the end call the XOR function which TA helped me createa
            
            final_bv = BitVector(size = 0)
            #Flatten out and print
            for i in range(4):
                for j in range(4):
                    final_bv = final_bv + statearray[j][i]
            # output.write(final_bv.get_bitvector_in_hex())    
            return(final_bv)
#***********************************************************************************************************************************************************************************
    def x931 ( self, v0, dt, totalNum, outfile):
        V = v0
        
        out = open(outfile, 'w')
        for x in range(totalNum):
            I = self.encryption_image(dt)
            #I = AES.gen_state_array(I)
            R = self.encryption_image(I^V)
            #I = AES.gen_state_array(I)
            V = self.encryption_image(R^I)
            out.write(str(R.int_val()) + '\n')  # Write R value to file
            #R.write_to_file(out)
            print("R Value: ", R.int_val())
        out.close()

#*******************************************************************************************************************************************************************************

if __name__ == '__main__':
    cipher = AES(keyfile=sys.argv[3])
    if sys.argv[1] == '-e':
        cipher.encrypt(plaintext=sys.argv[2],ciphertext=sys.argv[4])
    elif sys.argv[1] == '-d':
        cipher.decrypt(ciphertext=sys.argv[2], decrypted=sys.argv[4])
    elif sys . argv [1] == "-i":
         cipher.ctr_aes_image(iv=BitVector(textstring ="counter-mode-ctr") ,image_file=sys.argv[2], enc_image=sys.argv[4])
    else :
        cipher.x931(v0=BitVector(textstring ="counter-mode-ctr"),dt=BitVector(intVal=501,size=128 ),totalNum=int(sys.argv[2]) ,outfile=sys.argv[4])

    # elif sys.argv[1] == '-i':
    #     sys.exit("Incorrect Command - Line Syntax")

