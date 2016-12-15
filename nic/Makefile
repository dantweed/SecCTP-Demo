all:active client

active:
	g++ active.cpp -o active.exe -ltins -lrt -lpthread 

client:
	gcc -o client.exe client.c ../secctp.c `pkg-config gnutls --cflags --libs` -lrt -lpthread -lncurses

debug: activedbg clientdbg

activedbg:
	g++ -DDEBUG -g -fstack-protector-strong active.cpp -o active.exe -ltins -lrt -lpthread 

clientdbg:
	gcc -DDEBUG -g -fstack-protector-strong -o client.exe client.c ../secctp.c `pkg-config gnutls --cflags --libs` -lrt -lpthread 




