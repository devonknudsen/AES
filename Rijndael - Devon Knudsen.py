######################################################################################################
# Name: Devon Knudsen
# Assignment: Rijndael (AES)
# Date: 8 May 2020
# Written in Python 2.7
######################################################################################################

from sys import stdin, stderr, stdout
from hashlib import sha256
from Crypto import Random
from Crypto.Cipher import AES

# the AES block size to use
BLOCK_SIZE = 16
# the padding character to use to make the plaintext a multiple of BLOCK_SIZE in length
PAD_WITH = "#"
# flag to use the dictionary as decipher method
USE_DICTIONARY = False
# file contianing dictionary as well as potential keys
DICTIONARY_FILE = "dictionary5.txt"
# threshold for the acceptable percentage of words
THRESHOLD = 0.9
# set min word length acceptable for deciphered text
MIN_WORD_LEN = 10
# flag to evaluate keys in reverse
REVERSE = False
# works with filter function to filter keys by first letter
# IS CASE SENSITIVE
KEY_FILTER = []
# predefined punctuation to assist in normalizing words
PUNCTUATION = " -,;:!?/.'\"()[]$&#%"
# flag to use a tag as a decipher method
USE_TAG = True
# defined tag to search for when deciphering
TAG = "%PDF-1.4"
# flag to end program after one passable decipher is printed
BREAK = True

# decrypts a ciphertext with a key
def decrypt(ciphertext, key):
	# hash the key (SHA-256) to ensure that it is 32 bytes long
    key = sha256(key).digest()
	# get the 16-byte IV from the ciphertext
	# by default, we put the IV at the beginning of the ciphertext
    iv = ciphertext[:16]

	# decrypt the ciphertext with the key using CBC block cipher mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
	# the ciphertext is after the IV (so, skip 16 bytes)
    plaintext = cipher.decrypt(ciphertext[16:])

	# remove potential padding at the end of the plaintext
	# figure this one out...
    if(not(TAG)):
        plaintext = plaintext.replace("#", "")
    
    return plaintext

# encrypts a plaintext with a key
def encrypt(plaintext, key):
	# hash the key (SHA-256) to ensure that it is 32 bytes long
	key = sha256(key).digest()
	# generate a random 16-byte IV
	iv = Random.new().read(BLOCK_SIZE)

	# encrypt the ciphertext with the key using CBC block cipher mode
	cipher = AES.new(key, AES.MODE_CBC, iv)
	# if necessary, pad the plaintext so that it is a multiple of BLOCK SIZE in length
	plaintext += (BLOCK_SIZE - len(plaintext) % BLOCK_SIZE) * PAD_WITH
	# add the IV to the beginning of the ciphertext
	# IV is at [:16]; ciphertext is at [16:]
	ciphertext = iv + cipher.encrypt(plaintext)

	return ciphertext

# normalizes candidate text by removing punctuation and new lines
# returns the normalized text
def normalizeTxt(pTxt):
    for p in PUNCTUATION:
        if(p != "'"):
            pTxt = pTxt.replace(p, "")
    
    pTxt = pTxt.replace("\n", " ")
    
    return pTxt

# filters out keys if their first letter is not within the KEY_FILTER list
def filterKeys(keys):
    keysToRemove = []
    for key in keys:
        if(key[0] in KEY_FILTER):
            continue
        else:
            keysToRemove.append(key)
    
    for key in keysToRemove:
        keys.remove(key)

    return keys

# MAIN
cipherTxt = stdin.read().rstrip("\n")

file = open(DICTIONARY_FILE, "r")
pKeys = file.read().rstrip("\n").split("\n")
file.close()

# create normalized lowercase dictionary
lowerDictionary = []
for word in pKeys:
    lowerDictionary.append(word.lower())
      
# filter keys if a letter is placed in the list
if(len(KEY_FILTER) > 0):
    pKeys = filterKeys(pKeys)

# changes the bounds of the follwoing for loop depending
# on if the keys should be processed forwards or backwards
if REVERSE == False:
    start = 0
    end = len(pKeys)
    step = 1
else:
    start = len(pKeys) - 1
    end = -1
    step = -1

for i in range(start, end, step):
    plainTxt = decrypt(cipherTxt, pKeys[i])
    if(USE_DICTIONARY == True):
        words = plainTxt.split(" ")
        count = 0
        amountOfWords = len(words)
        for x in range(len(words)):
            normalizedWord = normalizeTxt(words[x]).lower()
            
            # if normalization caused two complete words to be held within a single string (removal of a new line)
            if(" " in normalizedWord):
                spaceIndx = normalizedWord.index(" ")
                normalizedWord = normalizedWord.replace(" ", "")
                firstWord = normalizedWord[:spaceIndx]
                secondWord = normalizedWord[spaceIndx:]
                if(firstWord in lowerDictionary):
                    count += 1
                if(secondWord in lowerDictionary):
                    count += 1
                
                # increasing count of the amount of words within the candidate text accounts for the two words
                # bound together within a single string by a new line
                amountOfWords += 1
                
            elif(normalizedWord in lowerDictionary):
                count += 1
            
        if(amountOfWords < MIN_WORD_LEN):
            continue
        
        if((float(count)/float(amountOfWords)) >= THRESHOLD):
            print("KEY={}".format(pKeys[i]))
            print(plainTxt)
            if(BREAK == True):
                exit(0)
        
    elif(USE_TAG == True):
        # if the predefined tag is found within the deciphered text
        if(TAG in plainTxt[:len(TAG)]):
            
            # write the bytes to the output (should be a file)
            stdout.write(plainTxt)
            
            stderr.write("KEY={}".format(pKeys[i]))
            if(BREAK == True):
                exit(0)
    
    # print all possibilities regardless of tag or dictionary
    else:
        print("KEY={}".format(pKeys[i]))
        print(plainTxt)