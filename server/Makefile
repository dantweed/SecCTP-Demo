all:server web

web:
	gcc -o webserver/web.exe webserver/http.c -lmicrohttpd -lrt 

server:
	gcc -o server.exe server.c ../secctp.c `pkg-config gnutls --cflags --libs` -lrt -lpthread 

debug: webddg serverdbg


webddg:
	gcc -DDEBUG -g -fstack-protector-strong -o webserver/web.exe webserver/http.c -lmicrohttpd -lrt 

serverdbg:
	gcc -DDEBUG -g -fstack-protector-strong -o server.exe server.c ../secctp.c `pkg-config gnutls --cflags --libs` -lrt -lpthread 


