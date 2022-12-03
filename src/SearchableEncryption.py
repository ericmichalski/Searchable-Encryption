from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
from base64 import b64encode, b64decode
import ast
import sys

# Generate two secret keys, one for prf and aes each
def KeyGen(length = 256, skprf = "../data/skprf.txt", skaes = "../data/skaes.txt"):
    # Divide length by 8 to get bytes instead of bits for encryption purposes
    byteLen = int(int(length) / 8)
    prfKey = get_random_bytes(byteLen)
    prfFile = open(skprf, "wb")
    prfFile.write(prfKey)
    print("prfKey:",prfKey)
    prfFile.close()

    aesKey = get_random_bytes(byteLen)
    aesFile = open(skaes, "wb")
    aesFile.write(aesKey)
    print("aesKey:",aesKey)
    aesFile.close()


    # Extract each keyword from each file, then encrypt each with PRF
    # Then build an inverted index (or keyword file matrix)
    # Then write the index to a file
    # Then encrypt all data files with AES and write ciphertexts to a set of files
def Enc(skprf = "../data/skprf.txt", skaes = "../data/skaes.txt", index = "../data/index.txt", files = "../data/files", cipherTextFiles = "../data/ciphertextfiles.txt"):
    # Read prf and aes keys from files
    prfFile = open(skprf, "rb")
    skprfKey = prfFile.read()

    aesFile = open(skaes, 'rb')
    skaesKey = aesFile.read()

    # Extract each keyword from each file in the files directory
    fileList = os.listdir(files)
    tempKeys = []
    cipherKeys = []
    count = 1
    for file in fileList:
        openFile = open(files + "/" + file, "r")
        for line in openFile:
            keyList = line.split()
            for key in keyList:
                if (key not in tempKeys):
                    tempKeys.append(key)

                    # Make encryption cipher from PRF key and encrypt each different key
                    prfCipher = AES.new(skprfKey, AES.MODE_CBC, iv=b'0123456789abcdef')
                    padded_data = pad(key.encode(), prfCipher.block_size)
                    cipherText = prfCipher.encrypt(padded_data)

                    # Append each encrypted key to a list
                    cipherKeys.append(cipherText)


        # Encrypt all the files and write each to a cipher file in ../data/ciphertextfiles/c# where # is the number of the file
        aesCipher = AES.new(skaesKey, AES.MODE_CBC, iv=b'0123456789abcdef')
        openFile.seek(0)
        padded_dataAES = pad(openFile.read().encode(), AES.block_size)
        cipherFileData = aesCipher.encrypt(padded_dataAES)

        with open("../data/ciphertextfiles/c" + str(count) + ".txt", "wb") as newCipherFile:
            newCipherFile.write(cipherFileData)
            newCipherFile.close()
        count = count + 1
    
    # Create 2d index and add cipherKeys to each row
    index = [[] for i in range(len(tempKeys))]
    x = 0
    for cipherKey in cipherKeys:
        index[x].append(b64encode(cipherKey))
        x = x + 1

    # For each file, mark in the index if a key is in the file
    j = 1
    for file in fileList:
        openFile = open(files + "/" + file, "r")
        inFile = []
        for line in openFile:
            keyList = line.split()
            for tempKey in tempKeys:
                if (tempKey in keyList):
                    inFile.insert(count - 1, "c" + str(j) + ".txt")
                else:
                    inFile.insert(count - 1, 0)
        x = 0
        for val in inFile:
            index[x].append(val)
            x = x + 1
        j = j + 1

    # Write index to file
    with open("../data/index.txt", "w") as indexFile:
        print("Index")
        for row in index:
            indexFile.write(str(row) + '\n')
            print(row)
        indexFile.close()


# Encrypt the given keyword with the PRF key and write it to a token file
def TokenGen(keyword = "packers", skprf = "../data/skprf.txt", tokenFileLoc = "../data/token.txt"):
    with open(skprf, "rb") as prfFile:
        skprfKey = prfFile.read()

        prfCipher = AES.new(skprfKey, AES.MODE_CBC, iv=b'0123456789abcdef')
        padded_data = pad(keyword.encode(), prfCipher.block_size)
        tokenCipher = prfCipher.encrypt(padded_data)
        print("GENERATED TOKEN:", b64encode(tokenCipher))
        prfFile.close()
    with open(tokenFileLoc, "wb") as tokenFile:
        tokenFile.write(tokenCipher)
        tokenFile.close()


# Search the keyword
def Search(indexLoc = "../data/index.txt", tokenFileLoc = "../data/token.txt", cipherTextFiles = "../data/ciphertextFiles", skaes = "../data/skaes.txt", resultsFileLoc = "../data/results.txt"):
    # Retrieve the token from the token file
    tokenFile = open(tokenFileLoc, "rb")
    token = tokenFile.read()

    # Retrieve the index from the index file
    indexFile = open(indexLoc, "r")
    index = []
    for line in indexFile:
        x = line.rstrip()
        x = ast.literal_eval(x)
        index.append(x)
    
    # Retrieve the row from the matched token and get each associated cipher file
    cipherFiles = []
    for row in index:
        if (row[0] == b64encode(token)):
            for count, el in enumerate(row):
                if (count != 0 and el != 0):
                    cipherFiles.append(el)

    if (len(cipherFiles) > 0):
        print(*cipherFiles)
        print('\n', end='')
    else:
        print("No token found or token is not in files")

    # Decode the associated cipherfiles and print each files decrypted contents
    # Then write to results file. If no token is found, results file will be empty
    with open(resultsFileLoc, "w") as resultsFile:
        for x, cipherFile in enumerate(cipherFiles):
            openCipherFile = open(cipherTextFiles + "/" + cipherFile, "rb")
            cipherText = openCipherFile.read()
            skaesFile = open(skaes, "rb")
            skaesKey = skaesFile.read()

            aesCipher = AES.new(skaesKey, AES.MODE_CBC, iv=b'0123456789abcdef')
            message = unpad(aesCipher.decrypt(cipherText), AES.block_size).decode("utf-8")
            cipherFileName = cipherFiles[x]

            print(cipherFileName, message)
            resultsFile.write('{0} {1}\n'.format(cipherFileName, message))
        resultsFile.close()
    

# Input checks
if len(sys.argv) > 1:
	if sys.argv[1] == "KeyGen":
		if len(sys.argv) > 4:
			KeyGen(sys.argv[2], sys.argv[3], sys.argv[4])
		else:
			print("Not enough arguments (key length, skprf file, skaes file), using default values")
			KeyGen()
	elif sys.argv[1] == "Enc":
		if len(sys.argv) > 6:
			Enc(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
		else:
			print("Not enough arguments (skprf file, skaes file, index file, files dir, ciphertextfiles dir), using default values")
			Enc()
	elif sys.argv[1] == "TokenGen":
		if len(sys.argv) > 4:
			TokenGen(sys.argv[2], sys.argv[3], sys.argv[4])
		else:
			print("Not enough arguments (keyword, skprf file, token file), using default values")
			TokenGen()
	elif sys.argv[1] == "Search":
		if len(sys.argv) > 6:
			Search(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
		else:
			print("Not enough arguments (index file, token file, ciphertextfiles dir, skaes file, results file), using default values")
			Search()
else:
    # Calls default functions
    KeyGen()
    Enc()
    TokenGen()
    Search()