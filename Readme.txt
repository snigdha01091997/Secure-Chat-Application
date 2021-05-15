Task1 :
   All the necessary certificates required to establish TLS communication are generated using openssl
commands and are kept in the necessary containers.The certificates are stored in the "TLSCerts"
directory of Alice and Bob Container.
-----------------------------------------------------------------------------------------------------
Task 2:
  The program secure_chat_app.c is a socket program in C which supports TLS connection over normal
TCP connection.Here two parties are establishing the communication by TLS handshake using necessary
certificates.For this we have included SSL C functions and header files.Basically the same program
can be used as both server and client depending upon the arguements.
-----------------------EXECUTE-----------------------------------------------------------------------
To compile the code : make 
To run as a server[Bob]    :./secure_chat_app -s
To run aa a client[Alice]  :./secure_chat_app -c bob1
---------------------------------------------------------------------------------------------------
Task 3:
   The secure_chat_interceptor.c does downgrade attack and makes the communication between Alice and 
Bob unsecure .Before executing the above program it is necessary to poison the /etc/host file of Alice
/Bob .
-------------------------------EXECUTE--------------------------------------------------------------
poison the dns: bash ~/poison-dns-alice1-bob1.sh
To compile the code: make
To run the code:./secure_chat_interceptor -d alice1 bob1
Unpoison the dns:bash ~/unpoison-dns-alice1-bob1.sh
---------------------------------------------------------------------------------------------------
Task 4:
  Here the program secure_chat_interceptor.c does MITM attack by sharing fake certificates with Alice
and Bob.So here we generated the fake certificates using openssl command and verified it as a valid ones.
The fake certificates are stored in the "FakeCerts" directory of Trudy container.Trudy sends chat_STARTTLS
to Bob and starts sharing these verified fake certificates.
-------------------------------EXECUTE-----------------------------------------------------------------
poison the dns: bash ~/poison-dns-alice1-bob1.sh
To compile the code: make
To run the code:./secure_chat_interceptor -m alice1 bob1
Unpoison the dns:bash ~/unpoison-dns-alice1-bob1.sh
------------------------------------------------------------------------------------------------------------





 