# ########################################################################################## #
# Assignment: Secure Messaging                                              	             #
# Class: CS 4480 Computer Networks							     #
# Program: AliceTheClient.py 								     #
# By: xrawlinson									     #
# Last Update Date: 4/19/2016								     #
#											     #
# Description: AliceTheClient runs as a client that requests to connect to                   #
# 			   BobTheServer, after the connection is setup Alice sends a plain   #
# 			   hello message to Bob asking for his public key. After receiving   #
#			   and verifying the message from Bob, Alice uses Bob's public key,  #
#			   to encrypt an iv and a Symmetric key she generated. She also      #
#		       uses her own private key to sign her message, and encrypts            #
#			   the signed message and the actual message with the iv and the     #
#			   Symmetric key she generated. Then she wraps everything together   #
# 			   to one encrypted message and sends it to BobTheServer.            #         
# ########################################################################################## #

import socket 
import sys
import ast
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA
import pickle

#main()
def main():
	# calls the function alice_the_client()
	alice_the_client()
# end of main()

# alice_the_client() requests a connection to BobTheServer, after the connection is setup
# it calls the function sendsHello to send a hello message asking for Bob's public key
# and calls the function sendsEncryptedMSG to send an encrypted message after Bob's public key 
# is obtained and verified
def alice_the_client():
	try:
		# port number needs to be specified from the command line, if not specified will use default: 8000
		if(len(sys.argv) > 2):
			print "Invalid input. Please enter one argument for a port number OR none to use the default port number 8000."
			sys.exit(1)
		if(len(sys.argv) < 2):
			PORT = 8000
		else:
			PORT = int(sys.argv[1])

		# allows to specify a host, if none provided will be default to localhost
		HOST = raw_input("\nEnter a valid host you want to connect to OR press enter key to use localhost: ")
		if HOST == "":
			HOST = 'localhost'
			print "\nUsing 'localhost' since none was provided ...\n"

		# first to send hello to ask for the public key
		print "\nSending a 'hello' message to Bob ...\n"
		message1 = "Hello! Please send me your public key."
		fromBob = sendsHello(HOST, PORT, message1)

		# if the public key is actually from Bob after verification, sends the message
		message2 = raw_input("\nInput your message and press enter at the end of your message: ")
		print "\n*****************************************************************"			# <------ used for testing
		print "MESSAGE:", message2			
		print "\n*****************************************************************"			# <------ used for testing 					# <------ used for testing
		sendsEncryptedMSG(HOST, PORT, message2, fromBob)

		sys.exit(1)	

	# if command line enters CTRL+C, prints a message to advise and exist	
	except KeyboardInterrupt:
		print "\nYou requested to close. Bye!"
		sys.exit(1)	
# end of alice_the_client

# sets up connection with server
def connect(HOST, PORT):		
	try:
		# creates a socket for alice_the_client(), use SOCK_STREAM for TCP 
		sock_for_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		##print "Got a socket: ", sock_for_client.fileno()       # <------ used for testing

		# connects
		sock_for_client.connect((HOST, PORT))
		##print "\nBound to: ", sock_for_client.getsockname()	  # <------ used for testing

	except socket.error as details:
		# socket opened in error, closes it
		if sock_for_client:                      
			sock_for_client.close()
		# print the details, exits the program
		print "Issue opening socket: ", details
		sys.exit(1)

	return sock_for_client
# end of connect

# sends the hello message to obtain Bob's public key
def sendsHello(host, port, message):

	# sets up connection
	sock_for_client = connect(host,port)

	print "\n*****************************************************************"			# <------ used for testing
	# sends the message
	print "SENDING TO BOB: ", message
	sock_for_client.sendall(message)

	# buffer to store data being received from Bob
	receiveFromBob = ""

	while 1:			
		recv = sock_for_client.recv(1024)

		# if no more data to be received, break the while loop
		if not recv:
			break
		else:
			receiveFromBob += recv

	print "\n*****************************************************************"			# <------ used for testing
	print "RECEIVED FROM BOB: ", receiveFromBob			# <------ used for testing
	print "\n*****************************************************************"			# <------ used for testing
	# splits the received data to pieces base on spaces
	splitted = receiveFromBob.split(" ")

	print "\nExtracting the certificate ...\n"
	# stores the splitted data properly, converts string back to tuple
	certificate = eval(splitted[0])
	print "\n*****************************************************************"			# <------ used for testing
	print "CERTIFICATE: ", certificate				# <------ used for testing
	print "\n*****************************************************************"			# <------ used for testing

	print "Extracting the rest of the message and decrypting everything ...\n"
	encFirstChunk = eval(splitted[1])
	##print "FIRST CHUNK: ", encFirstChunk
	encSecondChunk = eval(splitted[2])
	##print "SECOND CHUNK: ", encSecondChunk
	encThirdChunk = eval(splitted[3])
	##print "THIRD CHUNK: ", encThirdChunk
	encForthChunk = eval(splitted[4])
	##print "FORTH CHUNK: ", encForthChunk

	# reads Alice's private key that was generated and stored before running the program
	aliceprivatekey = RSA.importKey(readAFile("aliceprivatekey.pem"))	

	# decrypts each chunk
	decFirstChunk = aliceprivatekey.decrypt(encFirstChunk)
	decSecondChunk = aliceprivatekey.decrypt(encSecondChunk)
	decThirdChunk = aliceprivatekey.decrypt(encThirdChunk)
	decForthChunk = aliceprivatekey.decrypt(encForthChunk)

	print "\n*****************************************************************"			# <------ used for testing
	print "DECRYPTED FIRST CHUNK: ", decFirstChunk
	print "\n*****************************************************************"			# <------ used for testing
	print "DECRYPTED SECOND CHUNK: ", decSecondChunk
	print "\n*****************************************************************"			# <------ used for testing
	print "DECRYPTED THIRD CHUNK: ", decThirdChunk
	print "\n*****************************************************************"			# <------ used for testing
	print "DECRYPTED FORTH CHUNK: ", decForthChunk
	print "\n*****************************************************************"			# <------ used for testing

	# put the decrypted chunks back together
	putBackTogether = decFirstChunk+decSecondChunk+decThirdChunk+decForthChunk

	# loads it back to the original format
	thawed = pickle.loads(putBackTogether)

	# reads Bob's public certificate key that was generated and stored before running the program
	certpublickey = RSA.importKey(readAFile("certpublickey.pem"))		# <------ used for testing

	# verifies the signature
	hashedBobPubKey_decrypted = SHA.new(putBackTogether).digest()
	##print "HASHED BOB'S DECRYPTED PUBLIC KEY: ", hashedBobPubKey_decrypted	# <------ used for testing
	##print "\n*****************************************************************"			# <------ used for testing

	print "\nPutting them together and unwrapping it ...\n"

	if certpublickey.verify(hashedBobPubKey_decrypted, certificate):
		print "\n*****************************************************************"			# <------ used for testing
		print "OBTAINED DECRYPTED BOB'S PUBLIC KEY: ", thawed		# <------ used for testing	
		print "\n*****************************************************************"			# <------ used for testing
		print "\nVerifying to ensure it was actually from Bob ...\n"
   		print "\nYay! It was from Bob! Good to proceed..."				# <------ used for testing

   	else:
   		print "\nIt was NOT from Bob, exiting..."		# <------ used for testing
		sys.exit(1)	

	# returns Bob's public key
	return thawed

	sock_for_client.close()
# end of sendsHello

# encrypts the message and sends it to Bob
def sendsEncryptedMSG(host, port, message, bobPublickey):

	# sets up the connection
	sock_for_client = connect(host,port)

	print "Start encrypting the message ...\n"
	print "Getting the iv and Symmetric key ... \n"

################# this part is for encrypting the iv and Symmetric key with Bob's public key ###############################

	# gets the iv
	iv = Random.new().read(AES.block_size)	
	print "\n*****************************************************************"			# <------ used for testing
	print "IV: ", iv 		# <------ used for testing
	print "\n*****************************************************************"			# <------ used for testing
	# gets the key
	key = Random.new().read(16)
	print "SYMMETRIC KEY: ", key  	# <------ used for testing
	print "\n*****************************************************************"			# <------ used for testing
	print "\nCombining them ...\n"
	# ivAndSymKey appends the iv and the Symmetric key
	ivAndSymKey = iv + "     " + key
	print "\n*****************************************************************"			# <------ used for testing
	print "COMBINED IV AND SYMMETRIC KEY: ", ivAndSymKey
	print "\n*****************************************************************"			# <------ used for testing

	print "\nEncrypting them with Bob's public key ...\n"
	# encrypts the iv and the symmetric key and with Bob's public key
	encWithBobPubKey = bobPublickey.encrypt(ivAndSymKey, 32)
	print "\n*****************************************************************"			# <------ used for testing
	print "AFTER ENCRYPTION: ", encWithBobPubKey
	print "\n*****************************************************************"			# <------ used for testing

	# will be used to do encryption
	cipher = AES.new(key, AES.MODE_CFB, iv)

################### this part is to sign the message with Alice's private key and append the message to it ######################

	# reads Alice's private key that was generated and stored before running the program
	aliceprivatekey = RSA.importKey(readAFile("aliceprivatekey.pem"))

	# hash the message
	hashedMsg = SHA.new(message).digest()	
	print "\nHashing the original message ...\n"
	print "\n*****************************************************************"			# <------ used for testing
	print "HASHED MESSAGE: ", hashedMsg											# <------ used for testing
	print "\n*****************************************************************"         # <------ used for testing
	# signs the hashed message with Alice's private key
	signWithAlicePrivKeyMsg = aliceprivatekey.sign(hashedMsg, '')
	print "\nSigning the hashed message with Alice's private key ...\n"
	print "\n*****************************************************************"			# <------ used for testing
	print "SIGNED MESSAGE: ", signWithAlicePrivKeyMsg		    # <------ used for testing
	print "\n*****************************************************************"			# <------ used for testing

	print "\nCombining the signed message with the actual message ...\n"
	# combines the singed message with the actual message
	msgCombined = pickle.dumps(signWithAlicePrivKeyMsg)+ "     " + message
	print "\n*****************************************************************"			# <------ used for testing
	print "COMBINED MESSAGE: ", msgCombined
	print "\n*****************************************************************"			# <------ used for testing

################### this part is to use the iv and Symmetric key to encrypt the signed message and message combination ############

	print "\nEncrypting the combined message with the iv and Symmetric Key...\n"
	# get the combined message size
	size = sys.getsizeof(msgCombined)
	print "\nThe message is too large, breaking them to chunks to encrypt...\n"
	# initialize a buffer to store the chunks
	blocks = [size/32]
	# as long as there is data, stores them
	for i in range(1, size):
		blocks = chunks(msgCombined, 32)

	# initialize a buffer to store encrypted chunks
	allChunks = ""
	print "\n*****************************************************************"			# <------ used for testing
	for chunk in blocks:		
		print "\nCHUNK: ", chunk
		# encrypts each chunk	
		encryptedChunk = cipher.encrypt(chunk)	
		print "\nAFTER ENCRYPTION: ", encryptedChunk
		# use "     " in between so I can split it later
		allChunks = allChunks + "     " + encryptedChunk
		##print "COMBINED ENCRYPTED CHUNKS: ", allChunks
		print "\n*****************************************************************"			# <------ used for testing
	print "COMBINED ENCRYPTED CHUNKS: ", allChunks
	print "\n*****************************************************************"			# <------ used for testing

	print "\nCombining all the encrypted peices together ...\n"
	# appends everything, which will be sent to Bob (put "     " in between so I can split it when Bob receives it)
	wholeMsg = pickle.dumps(encWithBobPubKey) + "     "+ allChunks  										# <------ used for testing
	print "\n*****************************************************************"			# <------ used for testing
	print "THE WHOLE MESSAGE: ", wholeMsg
	print "\n*****************************************************************"			# <------ used for testing

	print "\nSending it to Bob ...\n"
	sock_for_client.sendall(wholeMsg)

##########################################################################################################################

	sock_for_client.close()
	sentence = raw_input("Press enter to exit.")
# end of sendsEncryptedMSG

# breaks string to chunks
def chunks(s, n):
    n = max(1, n)
    return [s[i:i + n] for i in range(0, len(s), n)]
# end of chunks

# reads a file
def readAFile(file):
	file_opened = open(file, 'r')
	## print file_opened		# <------ used for testing
	lines = file_opened.read()
	## print lines			# <------ used for testing
	return lines

if __name__ == '__main__':
    main()
