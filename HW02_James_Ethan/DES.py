from BitVector import *
import sys
import io

class DES ():
    # class constructor - when creating a DES object , the
    # class ’s constructor is called and the instance variables
    # are initialized

    # note that the constructor specifies each instance of DES
    # be created with a key file (str)
    def __init__ ( self , key ):
        # within the constructor , initialize instance variables
        # these could be the s-boxes , permutation boxes , and
        # other variables you think each instance of the DES
        # class would need .
        self.key = key
        self.expansion_permutation = [31,  0,  1,  2,  3,  4, 
                          3,  4,  5,  6,  7,  8, 
                          7,  8,  9, 10, 11, 12, 
                         11, 12, 13, 14, 15, 16, 
                         15, 16, 17, 18, 19, 20, 
                         19, 20, 21, 22, 23, 24, 
                         23, 24, 25, 26, 27, 28, 
                         27, 28, 29, 30, 31, 0]
        self.shifts_for_round_key_gen = ["111000001011111001101110101111111111110010111110",
                                            "111000001011011011110110100110110111111110101111",
                                            "111101001101011001110110111111100111101110110001",
                                            "111001101101001101110010111100110110101101111111",
                                            "101011101101001101110111111101111011101110011010",
                                            "101011110101001101011011111101010011011101111111",
                                            "001011110101001111111001011111111011101011101110",
                                            "100111110101100111011001011101001111110111111111",
                                            "000111110100100111011011111111101111110110001101",
                                            "001111110110100110011101111010100111011111111011",
                                            "000111110010110110001101111111111111101100101011",
                                            "010110110010110010111101111101100101111101111010",
                                            "110111011010110010101100110111011011101101111110",
                                            "110100101010111010101110111101011111111011111000",
                                            "111110001011111000100110011110011011111001111111",
                                            "111100011011111000100110111110101101011110111101"]
        self.p_box = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]

        self.s_boxes = {i:None for i in range(8)}

        self.s_boxes[0] = [ [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
                    [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
                    [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
                    [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13] ]

        self.s_boxes[1] = [ [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
                    [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
                    [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
                    [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9] ]

        self.s_boxes[2] = [ [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
                    [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
                    [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
                    [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12] ]

        self.s_boxes[3] = [ [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
                    [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
                    [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
                    [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14] ]

        self.s_boxes[4] = [ [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
                    [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
                    [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
                    [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3] ]  

        self.s_boxes[5] = [ [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
                    [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
                    [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
                    [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13] ]

        self.s_boxes[6] = [ [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
                    [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
                    [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
                    [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12] ]

        self.s_boxes[7] = [ [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
                    [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
                    [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
                    [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11] ]
        self.key_permutation_1 = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,
                            9,1,58,50,42,34,26,18,10,2,59,51,43,35,
                            62,54,46,38,30,22,14,6,61,53,45,37,29,21,
                            13,5,60,52,44,36,28,20,12,4,27,19,11,3]

        self.key_permutation_2 = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,
                            3,25,7,15,6,26,19,12,1,40,51,30,36,46,
                            54,29,39,50,44,32,47,43,48,38,55,33,52,
                            45,41,49,35,28,31]

    def convert_keys(self, str_key_list):
        bv_list = []

        for i in str_key_list:
            fp_read = io.StringIO(i)
            bv_list.append(BitVector(fp=fp_read))

        return bv_list

    # encrypt method declaration for students to implement
    # Inputs : message_file (str), outfile (str)
    # Return : void
    def encrypt ( self , message_file , outfile ):
        # encrypts the contents of the message file and writes
        # the ciphertext to the outfile

        bv = BitVector(filename=message_file)
        FILEOUT = open(outfile, 'w')  # Open the output file   
        while bv.more_to_read:
            bitvec = bv.read_bits_from_file(64)#Read 64 characters at a time from input file
            #if we reach end of file then we want to get out meaning we reached end and close the file
            if(bitvec.length() == 0): 
                break  
            #must account for padding if needed
            bitvec.pad_from_right(64 - bitvec.length()) #accound for any sort of padding
            #process and write to output file
            encrypted_block = self._process_block(bitvec)
            #Write to output file in in single line hex string
            FILEOUT.write(encrypted_block.get_bitvector_in_hex())
      

        #Closed opened files   
        FILEOUT.close()
    
    def _process_block(self, block)->BitVector:
        #split block into left and right halves
        [LH,RH] = block.divide_into_two()
        #DO PERMUTATION AND XORING
        #implement fiestel structure, isnt it supposed to be built in already
        round_keys = self.convert_keys(self.shifts_for_round_key_gen)
        for round_num in range(16): #Should still run???????????????????????????????????????????
            newRE = RH.permute(self.expansion_permutation) #go through permuation
            out_xor = newRE^(round_keys[round_num]) #Do the XORING
            substitue_var = self.substitute(out_xor) #Call the subsitituiton
            p_box_sub = substitue_var.permute(self.p_box)
            ##********************TA HELP******************************************************
            LH_Xor =  p_box_sub ^ LH
            LH = RH
            RH = LH_Xor
            ##**********************************************************************************
        # Final permutation
        final_permuted = RH + LH #Put back together
        return (final_permuted)
    
    def substitute( self, expanded_half_block):
        output = BitVector (size = 32)
        segments = [expanded_half_block[x*6:x*6+6] for x in range(8)]
        for sindex in range(len(segments)):

            row = 2*segments[sindex][0] + segments[sindex][-1]
            column = int(segments[sindex][1:-1])
            output[sindex*4:sindex*4+4] = BitVector(intVal = self.s_boxes[sindex][row][column], size = 4) #Changed it to self.s_boxes
        return output  
    
    def generate_round_keys(self,encryption_key):
        round_keys = []
        key = encryption_key.deep_copy()
        for round_count in range(16):
            [LKey, RKey] = key.divide_into_two()    
            shift = self.shifts_for_round_key_gen[round_count]
            LKey << shift
            RKey << shift
            key = LKey + RKey
            round_key = key.permute(self.key_permutation_2)
            round_keys.append(round_key)
        return round_keys
    
    def get_encryption_key(self, key):
        key = BitVector(textstring = key)
        key = key.permute(self.key_permutation_1)
        return key
##*********************************************************************************************************************************************************************
    # decrypt method declaration for students to implement
    # Inputs : encrypted_file (str), outfile (str)
    # Return : void
    def decrypt ( self , encrypted_file , outfile ):
        # decrypts the contents of the encrypted_file and
        # writes the recovered plaintext to the outfile

        #Open the files to be used
        file_pointer = open(encrypted_file, "r")
        for t in file_pointer:
            bv_decrypt = BitVector(hexstring = t) #Convert to a hexstring
        
        
        FILEOUT_decrypt = open(outfile, 'w')  # Open the output file
        for i in range (0, len(bv_decrypt) // 64):
            bitvec_d = bv_decrypt[64*i:64*(i+1)] #read chunks of 64 bits
            if (bitvec_d.length() == 0): #once you reach end of the file
                break
            decrypted_block = self._process_decrypt_block(bitvec_d) #process that section of 64 bits
            FILEOUT_decrypt.write(decrypted_block.get_text_from_bitvector()) #write to output file
        
        # Close opened files
        FILEOUT_decrypt.close()

    def _process_decrypt_block(self, block) -> BitVector:
    # Split block into left and right halves
        [LH, RH] = block.divide_into_two()
        # Do the decryption rounds in reverse order
        round_keys = self.convert_keys(self.shifts_for_round_key_gen) #get the round keys
        for round_num in range(15, -1, -1):  # Reverse order

            inital_RE = RH.deep_copy()
            newRE = RH.permute(self.expansion_permutation)
            out_xor = newRE ^ round_keys[round_num]
            substitute_var = self.substitute(out_xor)
            p_box_sub = substitute_var.permute(self.p_box)

            RH = p_box_sub ^ LH
            LH = inital_RE

        # Final permutation
        final_permuted = RH + LH  # Put back together
        return final_permuted
    
#****************************************************************************************************************************************************************************
    def encrypt_image(self, image_file, outfile):
        with open(image_file, 'rb') as file_point:
            # Read the first three lines (PPM header)
            l1 = file_point.readline()
            l2 = file_point.readline()
            l3 = file_point.readline()
            # Read the remaining image data
            #image_datas = file_point.read() #might not need!!!!!!!!!!!!!!
            image_datas = BitVector(filename=image_file)
        out = open(outfile, 'wb')
        out.write(l1)
        out.write(l2)
        out.write(l3)
        encrypted_image_data = self._process_image(image_datas, out) #Do DES PROCessing on all of data
        out.close()
       
    def _process_image(self, bv, out_file):
        # Process the image data block by block (64 bits at a time)
        # num_blocks = (len(image_data) * 8) // 64  # Calculate the number of blocks
        encrypted_blocks_list = []
        # bv_image = BitVector(rawbytes=image_data)
        while bv.more_to_read:
            bitvec = bv.read_bits_from_file(64)
            # if bitvec.length() == 0:
            #     break
            bitvec.pad_from_right(64 - bitvec.length())
            encrypted_block = self._process_block(bitvec)
            encrypted_block.write_to_file(out_file)
            #encrypted_blocks_list.append(encrypted_block)
 

#**************************************************************************************************************************************************************
# drive the encryption / decryption process
if __name__ == '__main__':
    cipher = DES(key=sys.argv[3])
    if sys.argv[1] == '-e':
        cipher.encrypt(sys.argv[2], sys.argv[4])
    elif sys.argv[1] == '-d':
        cipher.decrypt(sys.argv[2], sys.argv[4])
    elif sys.argv[1] == '-i':
        cipher.encrypt_image(sys.argv[2], sys.argv[4])
