#include "stdio.h"
#include "stdlib.h"
#include "sys/types.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include "arpa/inet.h"
#include "string.h"
#include "unistd.h"
#include <sys/epoll.h> 
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>




void  msg_cb(int write_p, int version, int content_type,
                        const void *buf, size_t len, SSL *ssl, void *arg)
{
    const char *str_write_p, *str_version, *str_content_type =
        "", *str_details1 = "", *str_details2 = "";

    str_write_p = write_p ? ">>>" : "<<<";

    switch (version) {
    case SSL2_VERSION:
        str_version = "SSL 2.0";
        break;
    case SSL3_VERSION:
        str_version = "SSL 3.0 ";
        break;
    case TLS1_VERSION:
        str_version = "TLS 1.0 ";
        break;
    case TLS1_1_VERSION:
        str_version = "TLS 1.1 ";
        break;
    case TLS1_2_VERSION:
        str_version = "TLS 1.2 ";
        break;
    case DTLS1_VERSION:
        str_version = "DTLS 1.0 ";
        break;
    case DTLS1_BAD_VER:
        str_version = "DTLS 1.0 (bad) ";
        break;
    default:
        str_version = "???";
    }

    if (version == SSL2_VERSION) {
        str_details1 = "???";

        if (len > 0) {
            switch (((const unsigned char *)buf)[0]) {
            case 0:
                str_details1 = ", ERROR:";
                str_details2 = " ???";
                if (len >= 3) {
                    unsigned err =
                        (((const unsigned char *)buf)[1] << 8) +
                        ((const unsigned char *)buf)[2];

                    switch (err) {
                    case 0x0001:
                        str_details2 = " NO-CIPHER-ERROR";
                        break;
                    case 0x0002:
                        str_details2 = " NO-CERTIFICATE-ERROR";
                        break;
                    case 0x0004:
                        str_details2 = " BAD-CERTIFICATE-ERROR";
                        break;
                    case 0x0006:
                        str_details2 = " UNSUPPORTED-CERTIFICATE-TYPE-ERROR";
                        break;
                    }
                }

                break;
            case 1:
                str_details1 = ", CLIENT-HELLO";
                break;
            case 2:
                str_details1 = ", CLIENT-MASTER-KEY";
                break;
            case 3:
                str_details1 = ", CLIENT-FINISHED";
                break;
            case 4:
                str_details1 = ", SERVER-HELLO";
                break;
            case 5:
                str_details1 = ", SERVER-VERIFY";
                break;
            case 6:
                str_details1 = ", SERVER-FINISHED";
                break;
            case 7:
                str_details1 = ", REQUEST-CERTIFICATE";
                break;
            case 8:
                str_details1 = ", CLIENT-CERTIFICATE";
                break;
            }
        }
    }

    if (version == SSL3_VERSION ||
        version == TLS1_VERSION ||
        version == TLS1_1_VERSION ||
        version == TLS1_2_VERSION ||
        version == DTLS1_VERSION || version == DTLS1_BAD_VER) {
        switch (content_type) {
        case 20:
            str_content_type = "ChangeCipherSpec";
            break;
        case 21:
            str_content_type = "Alert";
            break;
        case 22:
            str_content_type = "Handshake";
            break;
        }

        if (content_type == 21) { /* Alert */
            str_details1 = ", ???";

            if (len == 2) {
                switch (((const unsigned char *)buf)[0]) {
                case 1:
                    str_details1 = ", warning";
                    break;
                case 2:
                    str_details1 = ", fatal";
                    break;
                }

                str_details2 = " ???";
                switch (((const unsigned char *)buf)[1]) {
                case 0:
                    str_details2 = " close_notify";
                    break;
                case 10:
                    str_details2 = " unexpected_message";
                    break;
                case 20:
                    str_details2 = " bad_record_mac";
                    break;
                case 21:
                    str_details2 = " decryption_failed";
                    break;
                case 22:
                    str_details2 = " record_overflow";
                    break;
                case 30:
                    str_details2 = " decompression_failure";
                    break;
                case 40:
                    str_details2 = " handshake_failure";
                    break;
                case 42:
                    str_details2 = " bad_certificate";
                    break;
                case 43:
                    str_details2 = " unsupported_certificate";
                    break;
                case 44:
                    str_details2 = " certificate_revoked";
                    break;
                case 45:
                    str_details2 = " certificate_expired";
                    break;
                case 46:
                    str_details2 = " certificate_unknown";
                    break;
                case 47:
                    str_details2 = " illegal_parameter";
                    break;
                case 48:
                    str_details2 = " unknown_ca";
                    break;
                case 49:
                    str_details2 = " access_denied";
                    break;
                case 50:
                    str_details2 = " decode_error";
                    break;
                case 51:
                    str_details2 = " decrypt_error";
                    break;
                case 60:
                    str_details2 = " export_restriction";
                    break;
                case 70:
                    str_details2 = " protocol_version";
                    break;
                case 71:
                    str_details2 = " insufficient_security";
                    break;
                case 80:
                    str_details2 = " internal_error";
                    break;
                case 90:
                    str_details2 = " user_canceled";
                    break;
                case 100:
                    str_details2 = " no_renegotiation";
                    break;
                case 110:
                    str_details2 = " unsupported_extension";
                    break;
                case 111:
                    str_details2 = " certificate_unobtainable";
                    break;
                case 112:
                    str_details2 = " unrecognized_name";
                    break;
                case 113:
                    str_details2 = " bad_certificate_status_response";
                    break;
                case 114:
                    str_details2 = " bad_certificate_hash_value";
                    break;
                case 115:
                    str_details2 = " unknown_psk_identity";
                    break;
                }
            }
        }

        if (content_type == 22) { /* Handshake */
            str_details1 = "???";

            if (len > 0) {
                switch (((const unsigned char *)buf)[0]) {
                case 0:
                    str_details1 = ", HelloRequest";
                    break;
                case 1:
                    str_details1 = ", ClientHello";
                    break;
                case 2:
                    str_details1 = ", ServerHello";
                    break;
                case 3:
                    str_details1 = ", HelloVerifyRequest";
                    break;
                case 11:
                    str_details1 = ", Certificate";
                    break;
                case 12:
                    str_details1 = ", ServerKeyExchange";
                    break;
                case 13:
                    str_details1 = ", CertificateRequest";
                    break;
                case 14:
                    str_details1 = ", ServerHelloDone";
                    break;
                case 15:
                    str_details1 = ", CertificateVerify";
                    break;
                case 16:
                    str_details1 = ", ClientKeyExchange";
                    break;
                case 20:
                    str_details1 = ", Finished";
                    break;
                }
            }
        }
#ifndef OPENSSL_NO_HEARTBEATS
        if (content_type == 24) { /* Heartbeat */
            str_details1 = ", Heartbeat";

            if (len > 0) {
                switch (((const unsigned char *)buf)[0]) {
                case 1:
                    str_details1 = ", HeartbeatRequest";
                    break;
                case 2:
                    str_details1 = ", HeartbeatResponse";
                    break;
                }
            }
        }
#endif
    }
	printf("=======================start=============================\n");
    printf( "%s %s%s [length %04lx]%s%s\n", str_write_p, str_version,
               str_content_type, (unsigned long)len, str_details1,
               str_details2);

    if (len > 0) {
        size_t num, i;

        printf( "   ");
        num = len;
#if 0
        if (num > 16)
            num = 16;
#endif
        for (i = 0; i < num; i++) {
            if (i % 16 == 0 && i > 0)
               printf("\n   ");
            printf( " %02x", ((const unsigned char *)buf)[i]);
        }
        if (i < len)
            printf( " ...");
        printf( "\n");
    }

	printf("=======================end=============================\n");
}


void ssl_init()
{
	/* SSL 库初始化 */
    SSL_library_init();
    /* 载入所有 SSL 算法 */
    /* 载入所有 SSL 错误消息 */
    SSL_load_error_strings();
}

int main()
{
	int sock;
	int sub_proc = 0;
	pid_t fpid;
	int conn_fd;
	SSL_CTX* ctx;
	SSL* ssl;
	char buff[1024] = {0};
	const SSL_METHOD *meth = SSLv23_server_method();
	perror("start to work.");
	//创建一个socket
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock == -1)
	{
		perror("create socket fail.");
		exit(1);
	}

	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(443);
	server_addr.sin_addr.s_addr = inet_addr("0.0.0.0");
	

	//绑定socket的IP地址和端口
	if(bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0)
	{
		perror("bind fail.");
		close(sock);
		exit(1);
	}

	//开始监听端口
	if(listen(sock, 5) < 0)
	{
		perror("listen fail.");
		close(sock);
		exit(1);
	}
	fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);  

	//创建epoll_fd
	int epoll_fd = epoll_create(3);

	// 指定fd监听的事件
	struct epoll_event ev;
	ev.events = EPOLLIN  | EPOLLERR | EPOLLHUP;
	ev.data.fd = sock;
	if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0)
	{
		perror("epoll ctl fail.");
		close(epoll_fd);
		close(sock);
		exit(1);
	}

	while(1)
	{
		int wait_fds;
		struct epoll_event evs[10];
		if((wait_fds = epoll_wait(epoll_fd, evs, 10, 1000) )== -1)
		{
			perror("epoll wait fail.");
			close(epoll_fd);
			close(sock);
			exit(1);
		}
		if(wait_fds == 0)
		{
			printf("epoll wait timeout , continue;\n");
			continue;
		}
		printf("get wait  fd = %d\n", wait_fds);
		for(int i = 0; i< wait_fds; i++)
		{
			
			struct sockaddr_in cliaddr;
			socklen_t   len = sizeof( struct sockaddr_in );
		
			if(sub_proc == 0)
			{
				printf("get event %d\n.", i);
				if((conn_fd = accept(sock, (struct sockaddr*)&cliaddr, &len)) == -1)
				{
					perror("accept fail.\n");
					exit(1);
				}
				fcntl(conn_fd, F_SETFL, fcntl(conn_fd, F_GETFL, 0) | O_NONBLOCK); 
				printf("accept  %d\n.", i);
				fpid=fork();   
			    if (fpid < 0)   
			    {
			        printf("error in fork!\n");   
					return 0;
			    }
			    else if (fpid == 0) {
					printf("-->create sub proc success!\n");
			        sub_proc = 1;
					break;
			    }  
			    else {  
			        close(conn_fd);
					printf("parent continue;\n");
					continue;
			    }  
			}
		}
		if(sub_proc != 1)
			continue;
		
		close(epoll_fd);
		close(sock);
		epoll_fd = epoll_create(3);
		// 指定fd监听的事件
		ev.events = EPOLLIN  | EPOLLERR | EPOLLHUP;
		ev.data.fd = conn_fd;
		if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev) < 0)
		{
			perror("epoll ctl fail.");
			close(epoll_fd);
			close(sock);
			exit(1);
		}

		ssl_init();
		{
			ctx = SSL_CTX_new(meth);
			if(ctx == NULL)
			{
				perror("create SSL ctx fail.\n");
				close(epoll_fd);
				SSL_CTX_free(ctx);
				close(conn_fd);
				return 0;
			}
			if(SSL_CTX_use_certificate_file(ctx, "CAcert.pem", SSL_FILETYPE_PEM) <= 0)
			{
				perror("SSL_CTX_use_certificate_file fail.\n");
				ERR_print_errors_fp(stdout);
				close(epoll_fd);
				SSL_CTX_free(ctx);
				close(conn_fd);
				return 0;
			}
			if(SSL_CTX_use_PrivateKey_file(ctx, "privkey.pem", SSL_FILETYPE_PEM) <= 0)
			{
				perror("SSL_CTX_use_PrivateKey_file fail.\n");
				ERR_print_errors_fp(stdout);
				close(epoll_fd);
				SSL_CTX_free(ctx);
				close(conn_fd);
				return 0;
			}
			if(!SSL_CTX_check_private_key(ctx))
			{
				perror("SSL_CTX_check_private_key fail.\n");
				ERR_print_errors_fp(stdout);
				close(epoll_fd);
				SSL_CTX_free(ctx);
				close(conn_fd);
				return 0;
			}
			ssl = SSL_new(ctx);
			if(ssl == NULL)
			{
				perror("ssl new fial.\n");
				close(epoll_fd);
				SSL_CTX_free(ctx);
				close(conn_fd);
				return 0;
			}
			SSL_set_msg_callback(ssl, msg_cb);

			SSL_set_fd(ssl, conn_fd);
			if (SSL_accept(ssl) !=  1)
			{
				perror("ssl accept fail.\n");
				ERR_print_errors_fp(stdout);
				SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
				SSL_free(ssl);
				close(epoll_fd);
				SSL_CTX_free(ctx);
				close(conn_fd);
				printf("sub proc exit  error !\n");
				return 0;
			}

			SSL_read(ssl, buff, 1024);
			SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
			SSL_free(ssl);
			SSL_CTX_free(ctx);
			close(conn_fd);
			printf("sub proc exit");
			return 0;
		}
	}
	
	return 0;
}

#if 0
int main()
{
	int sock;
	int sub_proc = 0;
	pid_t fpid;
	int conn_fd;
	SSL_CTX* ctx;
	SSL* ssl;
	struct sockaddr_in cliaddr;
	socklen_t   len = sizeof( struct sockaddr_in );
	char buff[1024] = {0};
	const SSL_METHOD *meth = SSLv23_server_method();
	perror("start to work.");
	//创建一个socket
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock == -1)
	{
		perror("create socket fail.");
		exit(1);
	}

	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(443);
	server_addr.sin_addr.s_addr = inet_addr("0.0.0.0");

	//绑定socket的IP地址和端口
	if(bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0)
	{
		perror("bind fail.");
		close(sock);
		exit(1);
	}

	//开始监听端口
	if(listen(sock, 5) < 0)
	{
		perror("listen fail.");
		close(sock);
		exit(1);
	}

	

	while(1)
	{

		if((conn_fd = accept(sock, (struct sockaddr*)&cliaddr, &len)) == -1)
		{
			perror("accept fail.\n");
			exit(1);
		}
		(void)waitpid(0, NULL,WNOHANG);
		printf("accept  %d\n.",conn_fd);
		fpid=fork();   
	    if (fpid < 0)   
	    {
	        printf("error in fork!\n");   
			return 0;
	    }
	    else if (fpid != 0) {
			close(conn_fd);
			printf("parent continue;\n");
			continue;
	    }  
	    else {  
			break;	       
	    }  
	}
	
	close(sock);
	
	ssl_init();
	{
		ctx = SSL_CTX_new(meth);
		if(ctx == NULL)
		{
			perror("create SSL ctx fail.\n");
			close(conn_fd);
			return 0;
		}
		if(SSL_CTX_use_certificate_file(ctx, "CAcert.pem", SSL_FILETYPE_PEM) <= 0)
		{
			perror("SSL_CTX_use_certificate_file fail.\n");
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			close(conn_fd);
			return 0;
		}
		if(SSL_CTX_use_PrivateKey_file(ctx, "privkey.pem", SSL_FILETYPE_PEM) <= 0)
		{
			perror("SSL_CTX_use_PrivateKey_file fail.\n");
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			close(conn_fd);
			return 0;
		}
		if(!SSL_CTX_check_private_key(ctx))
		{
			perror("SSL_CTX_check_private_key fail.\n");
			ERR_print_errors_fp(stdout);
			SSL_CTX_free(ctx);
			close(conn_fd);
			return 0;
		}
		ssl = SSL_new(ctx);
		if(ssl == NULL)
		{
			perror("ssl new fial.\n");
			SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
			SSL_free(ssl);
			SSL_CTX_free(ctx);
			close(conn_fd);
			return 0;
		}
		SSL_set_msg_callback(ssl, msg_cb);
	
		SSL_set_fd(ssl, conn_fd);
		if (SSL_accept(ssl) == -1)
		{
			perror("ssl accept fail.\n");
			ERR_print_errors_fp(stdout);
			//SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
			SSL_free(ssl);
			SSL_CTX_free(ctx);
			close(conn_fd);
			return 0;
		}
	
		SSL_read(ssl, buff, 1024);
		//SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
		SSL_shutdown(ssl);
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		close(conn_fd);
		printf("sub proc exit");
	}
	return 0;
}
#endif
