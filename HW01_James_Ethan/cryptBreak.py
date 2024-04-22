from BitVector import BitVector
import sys

def cryptBreak (ciphertextFile , key_bv ):
    # file = open(ciphertextFile, "r")
    # store_cipher = file.read()
    # file.close()

    #** CODE ADPATED FROM PROF. AVI KAK
    PassPhrase = "Hopes and dreams of a million years"                          #(C)-
    BLOCKSIZE = 16                                                              #(D)-
    numbytes = BLOCKSIZE // 8                                                   #(E)-

    # Reduce the passphrase to a bit array of size BLOCKSIZE:
    bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)                                  #(F)-
    for i in range(0,len(PassPhrase) // numbytes):                              #(G)-
        textstr = PassPhrase[i*numbytes:(i+1)*numbytes]                         #(H)-
        bv_iv ^= BitVector( textstring = textstr )                              #(I)-

    # Create a bitvector from the ciphertext hex string:
    
    FILEIN = open(ciphertextFile)                                                  #(J)-
    encrypted_bv = BitVector( hexstring = FILEIN.read() )                       #(K)-
    FILEIN.close()
    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector( size = 0 )                                    #(T)-

    # Carry out differential XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv                                            #(U)-
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):                          #(V)-
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]                          #(W)-
        temp = bv.deep_copy()                                                   #(X)-
        bv ^=  previous_decrypted_block                                         #(Y)-
        previous_decrypted_block = temp                                         #(Z)
        bv ^=  key_bv                                                           #(a)-
        msg_decrypted_bv += bv                                                  #(b)-

    # Extract plaintext from the decrypted bitvector:    
    outputtext = msg_decrypted_bv.get_text_from_bitvector()                     #(c)-
    return(outputtext)

    # Write plaintext to the output file:
    # FILEOUT = open(sys.argv[2], 'w')                                            #(d)-
    # FILEOUT.write(outputtext)                                                   #(e)-
    # FILEOUT.close()                                                             #(f)-