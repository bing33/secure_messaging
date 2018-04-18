# ############################################################################## #
# Assignment: Secure Messaging                                              	 #
# Class: CS 4480 Computer Networks						 #
# Program: BobTheServer.py 							 #
# By: xrawlinson								 #
# Last Update Date: 4/19/2016							 #
#										 #										 #
# Description: BobTheServer runs as a server that allows connection from         #
#	       AliceTheClient, who will send messages to BobTheServer.           # 
#	       The first message is a plain hello message asking for Bob's       # 
#	       public key, after receiving it Bob signs and encrypts his         # 
#              public key then sends to Alice. The second message is an          # 
# 	       encrypted message, BobTheServer will decrypt the message.         #    		       
# ############################################################################## #

import socket 
import sys
import ast
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto import Random
import pickle

#main()
def main():
	# calls the function bob_the_server()
	bob_the_server()
# end of main()

# bob_the_server sets up a connection from alice_the_client, and it calls the function handlesRequest
def bob_the_server():

	try:
		# port number needs to be specified from the command line, if not specified will use default: 8000
		if(len(sys.argv) > 2):
			print "Invalid input. Please enter one argument for a port number or none to use the default port number 8000."
			sys.exit(1)
		if(len(sys.argv) < 2):
			PORT = 8000
		else:
			PORT = int(sys.argv[1])

		# host 
		HOST = ''

		try:
			# creates a socket for bob_the_server, use SOCK_STREAM for TCP 
			sock_for_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			## print 'Got a socket:', sock_for_server.fileno()       # <------ used for testing
			
			# uses the socket to bind the host and port
			sock_for_server.bind((HOST,PORT))
			## print 'Bound to:', sock_for_server.getsockname()	  # <------ used for testing
			
			# starts listening for connections
			sock_for_server.listen(1)
			print "\nReady to connect!\n"

		except socket.error as details:
			# socket opened in error, closes it
			if sock_for_server:                      
				sock_for_server.close()
			# print the details, exits the program
			print "\nIssue opening socket: ", details
			sys.exit(1)

		# bob_the_server accepts connection from the alice_the_client, calls the function handlesRequest
		while 1:
			conn_sock_for_server, client_addr = sock_for_server.accept()
			## print "conn_sock_for_server: ", conn_sock_for_server	# <------ used for testing
			##print "\n\n\n\n\n\n\n\nALICE'S ADDRESS: ", client_addr 		# <------ used for testing
			handlesRequest(conn_sock_for_server, client_addr)	

			conn_sock_for_server.close()

		sys.exit(1)	

	# if command line enters CTRL+C, prints a message to advise and exist	
	except KeyboardInterrupt:
		print "\nYou requested to close. Bye!"
		sys.exit(1)	
#end of funtion: bob_the_server()

# function handlesRequest receives the messages from Alice, and handles them base on the type of messages
def handlesRequest(client_conn, client_addr):

	# receives from Alice
	msgFromAlice = client_conn.recv(1024)

	# buffer to store data being received from Alice
	##msgFromAlice = ""

	##while 1:			
		##recv = client_conn.recv(1024)

		# if no more data to be received, break the while loop
		##if not recv:
			##break
		##else:
			##msgFromAlice += recv

	print "\nReceiving messages from Alice ...\n"			# <------ used for testing
	print "\n*****************************************************************"			# <------ used for testing
	print "RECEIVED MESSAGE: ", msgFromAlice		# <------ used for testing
	print "\n*****************************************************************"			# <------ used for testing

	# handles the messages based on what was received
	if msgFromAlice == "Hello! Please send me your public key.":
		print "\nReceived a 'hello' message from Alice asking for Bob's public key ...\n"
		# sends to Alice the encrypted/signed public key
		client_conn.send(signIt())
		print "\nSent the encrypted Bob's public key and the signed certificate to Alice..."
		print "\n*****************************************************************\n\n"			# <------ used for testing
	else:
		print "\nReceived an encrypted message from Alice ...\n"
		decrypt(msgFromAlice)
		print "\nDone receiving the message...\n"
# end of handlesRequest

# hashes Bob's public key and signs it with the certificate private key, also encrypts Bob's public key with Alice's public key
def signIt():
	# reads Bob's public key that was generated and stored before running the program
	print "\nImporting Bob's public key from storage ...\n"
	bobpublickey = RSA.importKey(readAFile("bobpublickey.pem"))	
	print "\n*****************************************************************"			# <------ used for testing	
	print "BOB'S PUBLIC KEY: ", bobpublickey		# <------ used for testing
	print "\n*****************************************************************"			# <------ used for testing

	print "\nStart signing and encrypting Bob's public key in order to send to Alice ...\n"
	# reads Alice's public key that was generated and stored before running the program
	alicepublickey = RSA.importKey(readAFile("alicepublickey.pem"))
	# reads Bob's private certificate key that was generated and stored before running the program
	certprivatekey = RSA.importKey(readAFile("certprivatekey.pem"))

	# Bob's public key is an instance, so needs to pickle it to string in order to encrypt and send via TCP
	frozen = pickle.dumps(bobpublickey)	

	# hashed frozen and generates the signature using certprivatekey
	hashedBobPubKey = SHA.new(frozen).digest()
	
	print "\nHashing the key ...\n"
	print "\n*****************************************************************"			# <------ used for testing
	print "HASHED KEY: ", hashedBobPubKey    	# <------ used for testing
	print "\n*****************************************************************"			# <------ used for testing

	print "\nSigning the hashed Bob's public key ...\n"
	certificate = certprivatekey.sign(hashedBobPubKey, '')
	print "\n*****************************************************************"			# <------ used for testing
	print "CERTIFICATE: ", certificate			# <------ used for testing
	print "\n*****************************************************************"			# <------ used for testing

	print "\nBreaking Bob's public key to chunks in order to enrypt due to RSA size limitation...\n"
	# due to RSA size limit, needs to break the large string to chunks
	blocks = [4]
	blocks = chunks(frozen, 110)

	# encrypts each chunk by using Alice's public key
	encFirstChunk = alicepublickey.encrypt(blocks[0], 32)
	encSecondChunk = alicepublickey.encrypt(blocks[1], 32)
	encThirdChunk = alicepublickey.encrypt(blocks[2], 32)
	encForthChunk = alicepublickey.encrypt(blocks[3], 32)

	print "\nEncrypting each chunk ...\n"
	print "\n*****************************************************************"			# <------ used for testing
	print "ENCRYPTED FIRST CHUNK: ", encFirstChunk
	print "\n*****************************************************************"			# <------ used for testing	
	print "ENCRYPTED SECOND CHUNK: ", encSecondChunk
	print "\n*****************************************************************"			# <------ used for testing	
	print "ENCRYPTED THIRD CHUNK: ", encThirdChunk
	print "\n*****************************************************************"			# <------ used for testing	
	print "ENCRYPTED FORTH CHUNK: ", encForthChunk	
	print "\n*****************************************************************"			# <------ used for testing	

	print "\nPutting everything together to one message to send to Alice ...\n"
	# put the certificate and encrypted chucks together, which will be sent to Alice
	messageToSend = repr(certificate) + " "+ repr(encFirstChunk) + " "+ repr(encSecondChunk) + " "+ repr(encThirdChunk) + " "+ repr(encForthChunk)
	print "\n*****************************************************************"			# <------ used for testing
	print "SENDING TO ALICE THE MESSAGE: ", messageToSend
	print "\n*****************************************************************"			# <------ used for testing	
	return messageToSend

def decrypt(msgFromAlice):
	# reads Bob's private key that was generated and stored before running the program
	bobprivatekey = RSA.importKey(readAFile("bobprivatekey.pem"))

	print "\nSplitting the received message to original chunks ...\n"
	# splits msgFromAlice to pieces 
	splitted = msgFromAlice.split("     ")

################# this part is for getting the iv and Symmetric key, which were encrypted with Bob's public key ###############

	# the first part, which was encrypted with Bob's public key
	thePartWasEncWithBobPubKey = pickle.loads(splitted[0])
	print "\n*****************************************************************"			# <------ used for testing
	print "THE PART THAT WERE ENCRYPTED WITH BOB'S PUBLIC KEY: ", thePartWasEncWithBobPubKey
	print "\n*****************************************************************"			# <------ used for testing

	print "\nDecypting it with Bob's private key ...\n"
	# decrypts the part that was encrypted with Bob's public key by using Bob's private key
	decWithBobPrivKey = bobprivatekey.decrypt(thePartWasEncWithBobPubKey)
	print "\n*****************************************************************"			# <------ used for testing
	print "AFTER DECRYPTION: ", decWithBobPrivKey
	print "\n*****************************************************************"			# <------ used for testing

	print "\nGetting the iv and Symmetric key ...\n"
	# splits decWithBobPrivKey to pieces 
	splitted2 = decWithBobPrivKey.split("     ")
	# gets the iv
	iv = splitted2[0]
	print "\n*****************************************************************"			# <------ used for testing
	print "IV: ", iv
	#gets the key
	key = splitted2[1]
	print "\n*****************************************************************"			# <------ used for testing
	print "KEY: ", key
	print "\n*****************************************************************"			# <------ used for testing

	# use the iv and Symmetric key to build the decryptor
	decryptor = AES.new(key, AES.MODE_CFB, iv)

######## this part is for getting the signed message and actual message, which were encrypted with the iv and Symmetric key  ########
	
	# stores all pieces, which will be the original signed message by Alice's private key
	restOfMsg = ""
	print "\nNow decpypting the rest of the message ...\n"
	print "\nThere are multiple chunks ...\n"
	print "\n*****************************************************************"			# <------ used for testing
	# gets all the pieces but the last one, which is the actual message
	for i in range(2, len(splitted)):
		print "CHUNK: ", splitted[i]
		decryptedData = decryptor.decrypt(splitted[i])
		print "AFTER DECRYPTION: ", decryptedData 
		restOfMsg = restOfMsg + decryptedData
		print "\n*****************************************************************"			# <------ used for testing
	print "\nCombining the chunks together ...\n"
	print "COMBINED MESSAGE: ", restOfMsg
	print "\n*****************************************************************"			# <------ used for testing

	print "\nExtracting data from it ...\n"
	# separates the signed message and the actual message
	splitted3 = restOfMsg.split("     ")

	signedMSG = splitted3[0]
	print "\nConverting to original signed message ...\n"
	signedMSG = pickle.loads(signedMSG)
	print "\n*****************************************************************"			# <------ used for testing
	print "ORIGINAL SIGNED MESSAGE: ", signedMSG
	print "\n*****************************************************************"			# <------ used for testing

	print "\nNow, getting the actual message ...\n"
	# now, gets the actual message
	messageFromAlice = splitted3[1]
	print "\n*****************************************************************"			# <------ used for testing
	print "MESSAGE FROM ALICE: ", messageFromAlice
	print "\n*****************************************************************"			# <------ used for testing

	print "\nVerifying the message to see if it was actually from Alice ...\n"
	print "\nHashing the message ...\n"
	# verifies the message from Alice
	hashedAliceMsg_decrypted = SHA.new(messageFromAlice).digest()
	print "HASHED ALICE'S MESSAG: ", hashedAliceMsg_decrypted							# <------ used for testing
	print "\n*****************************************************************"			# <------ used for testing

	# reads Alice's public key that was generated and stored before running the program
	alicepublickey = RSA.importKey(readAFile("alicepublickey.pem"))						# <------ used for testing
	print "\nVerifying ...\n"
	# verifies the signed message to ensure the message is actually from Alice
	if alicepublickey.verify(hashedAliceMsg_decrypted, signedMSG):
		print "Yay! It was from Alice!"
		print "\n*****************************************************************"			# <------ used for testing
	else:
		print "Ah oh! It was NOT from Alice!"
# end of decrypt

############################# below are some helper methods ###############################################################

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
# end of readAFile

if __name__ == '__main__':
    main()


