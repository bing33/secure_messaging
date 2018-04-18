# Secure Messaging

* Two Parts: BobTheServer and AliceTheClient

* To Run The Program: 

	1. CD to the correct folder (BobTheServer is in Bob’s folder and AliceTheClient is in Alice’s folder after you extracting the tar files)
	2. Run BobTheServer, there are two options:
		a. python BobTheServer.py 
		b. python BobTheServer.py PORTNUMBER (eg. python BobTheServer.py 7890)
	3. Run AliceTheClient, there are two options:
		a. if Bob did not provide a port number, it would run on default port 8000, then Alice can do the same: python AliceTheClient.py
		b. if Bob provided a port number, Alice will need to match: python AliceTheClient.py PORTNUMBER (eg. python AliceTheClient.py 7890)
        5. After BobTheServer is running and ready to connect, Alice can specify the server’s name or press ‘enter’ directly to use ‘localhost’ 
	   if you are testing both hosts on one machine.

* Details: 

	1. Alice’s first hello message will be send automatically to Bob, and Bob will encrypt/sign his public key then send to Alice.
	2. After Bob’s public key is verified by Alice, Alice will be able to enter a message via command line. The message then will be encrypted and send to Bob.
	3. Bob will decrypt the message and verify. 

* Note (Important): 
	
	1. Please do not load a text file (not supported), please enter the message for Alice via command line where the program is running.
	2. I have very detailed print lines to show you everything that Bob and Alice are doing. 
	3. Normally, the keys especially the private keys would be protected (not committed to public git accounts), but everything is committed at this time since this is just an exercise. When actually using the application, we would need to regenerate the keys and have them protected. 
