all:active client

active:
	g++ active.cpp -o active.exe -ltins -lrt -lpthread 

client:
	gcc -o client.exe client.c ../secctp.c `pkg-config gnutls --cflags --libs` -lrt -lpthread
