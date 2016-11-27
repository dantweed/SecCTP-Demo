all:web server

web:
	gcc -o webserver/web.exe webserver/http.c -lmicrohttpd -lrt

server:
	gcc -o server.exe server.c ../secctp.c `pkg-config gnutls --cflags --libs` -lrt -lpthread
