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
    int ca=SSL_CTX_load_verify_locations(sctx,"TLSCerts/root.crt", NULL); 
    int ke=SSL_CTX_use_PrivateKey_file(sctx, "TLSCerts/bob1-key.pem", SSL_FILETYPE_PEM);
    int ce=SSL_CTX_use_certificate_file(sctx, "TLSCerts/bob.crt", SSL_FILETYPE_PEM);
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
    
    SSL_CTX_set_verify(sctx,SSL_VERIFY_PEER,NULL);
    SSL_CTX_set_verify_depth(sctx,1);
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
    int ca=SSL_CTX_load_verify_locations(cctx,"TLSCerts/root.crt", NULL); 
    int ke=SSL_CTX_use_PrivateKey_file(cctx, "TLSCerts/alice1-key.pem", SSL_FILETYPE_PEM);
    int ce=SSL_CTX_use_certificate_file(cctx, "TLSCerts/alice.crt", SSL_FILETYPE_PEM);
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
    
    SSL_CTX_set_verify(cctx,SSL_VERIFY_PEER,NULL);
    SSL_CTX_set_verify_depth(cctx,1);
    return cctx;
}


void display(SSL* ssl)
{
	X509* certificate;
	char *l1,*l2;
	certificate=SSL_get_peer_certificate(ssl);
	if(certificate==NULL)
	{
		printf("\nNo certificate found");
	}
	else
	{	
		printf("\nCertificate is displayed as below:");
		l1=X509_NAME_oneline(X509_get_subject_name(certificate),0,0);
		printf("\nSubject of the certificate%s",l1);
		l2=X509_NAME_oneline(X509_get_issuer_name(certificate),0,0);
		printf("\nIssuer of the certificate%s",l2);
		free(l1);
		free(l2);
		X509_free(certificate);
	}
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
			printf("\nCertificate verification successful!");
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
	char c=getopt(argc,argv,"sc:");
	if(c=='s')
	{
		//server code
		int sd,bin,lis;
		struct sockaddr_in adr;
		sd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
		if(sd<0)
		{
			printf("\nsocket not created");
			exit(0);
		}
		adr.sin_family=AF_INET;
		adr.sin_port=htons(12120);
		adr.sin_addr.s_addr=inet_addr("172.31.0.3");
		bin=bind(sd,(struct sockaddr*)&adr, sizeof(adr));
		if(bin<0)
		{
			printf("\nnot binded");
			exit(0);
		}
		lis=listen(sd,2);
		if(lis<0)
		{
			printf("\nnot done");
			exit(0);
		}
		socklen_t l=sizeof(adr);
		int cli = accept(sd, (struct sockaddr*)&adr, &l);
		
		
		char buf[100] = {0};
    		while(strcmp(buf,"chat_close")!=0)
    		{
    			memset(buf,0,100);
    			int re = read(cli,buf,100);
    			printf("\nAlice:%s",buf);
    			if(strcmp(buf,"chat_close")==0)
			{
				close(cli);
    				close(sd);
    				exit(0);
			} 
    			if(strcmp(buf,"chat_STARTTLS")==0)
    			{
    				//recieved
    				char starttls[100];
    				printf("\nBob:");
    				gets(starttls);
    				char *starttlsreply=starttls;
  				if(strcmp(starttls,"chat_STARTTLS_ACK")==0)
  				{
    					send(cli,starttlsreply,strlen(starttlsreply),0); 
					printf("\nStarting Secure Communication:");
					SSL_CTX *ctx;
					SSL_library_init();
					ctx = serverCTX();
					SSL *ssl;
					ssl=SSL_new(ctx);
					SSL_set_fd(ssl,cli);
					communication(ssl);
					SSL_CTX_free(ctx);
					close(sd);
					close(cli);
					exit(0);
				}
				else
				{
					
					send(cli,starttlsreply,strlen(starttlsreply),0);
				}	
    			}
    			else
    			{
    			char str[100];
    			printf("\nBob:");
    			gets(str);
    			
    			char *msg=str;
    			send(cli,msg,strlen(msg),0);
    			if(strcmp(str,"chat_close")==0)
			{
    				close(sd);
    				close(cli);
    				exit(0);
			} 
    			}  
    		}
		close(sd);
		close(cli);
			
	}
	
	else if(c=='c')
	{
		//client code	
		struct hostent *host;
		const char *hostname=optarg;
		host=gethostbyname(hostname);
		int cd,con;
		struct sockaddr_in adr;
		cd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
		if(cd<0)
		{
			printf("\nsocket not created");
			exit(0);
		}
		adr.sin_family=AF_INET;
		adr.sin_port=htons(12120);
		adr.sin_addr.s_addr=*(long*)(host->h_addr);
		con=connect(cd, (struct sockaddr*)&adr, sizeof(adr));
		if (con!= 0)
    		{
        		close(cd);
        		printf("\nnot connected");
    		}
    		
    		char buf[100] = {0};
    		char str[100];
    		while(strcmp(buf,"chat_close")!=0)
    		{
    			memset(buf,0,100);
    			//memset(str,0,100);
    			printf("\nAlice:");
    			gets(str);
    			char *msg=str;
    			send(cd,msg,strlen(msg),0);
    			if(strcmp(str,"chat_close")==0)
			{
    				close(cd);
    				exit(0);
			}    
    			int re = read(cd,buf,100);
    			printf("\nBob:%s",buf);
    			if(strcmp(buf,"chat_close")==0)
			{
    				close(cd);
    				exit(0);
			} 
    			if(strcmp(buf,"chat_STARTTLS_ACK")==0)
    			{
    				char b[1024]={0};
    				printf("\nStarting Secure Communication");
 				SSL_CTX *ctx;
 				SSL *ssl;
				SSL_library_init();
				ctx = clientCTX();
				ssl=SSL_new(ctx);
				SSL_set_fd(ssl, cd);
				int co=SSL_connect(ssl);
				if (SSL_get_verify_result(ssl)==X509_V_OK) 
				{
					printf("\nCertificate verification successful!");
				}
				char mm[100];
				while(strcmp(b,"chat_close")!=0)
				{
					memset(b,0,1024);
					printf("\nAlice:");
					gets(mm);
					char *msg=mm;
					SSL_write(ssl,msg,strlen(msg));
					if(strcmp(mm,"chat_close")==0)
					{
						SSL_free(ssl);    			
    						SSL_CTX_free(ctx); 
    						close(cd);
    						exit(0);
					}  
        				int bytes = SSL_read(ssl, b, sizeof(b));
        				printf("\nBob:%s", b);
        				if(strcmp(b,"chat_close")==0)
					{
						SSL_free(ssl);    			
    						SSL_CTX_free(ctx); 
    						close(cd);
    						exit(0);
					}   
        				
        			}
        			
        			SSL_free(ssl);    			
    				SSL_CTX_free(ctx); 
    				close(cd);
    				exit(0);
    			}
    			
    			  
    		}
    		
    		
    		close(cd);
	}
	else
	{
		printf("Invalid option");
	}
}
