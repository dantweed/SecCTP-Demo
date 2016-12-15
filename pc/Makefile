all: 
	g++ -std=c++11 monitor.cpp -o monitor.exe -ltins -lboost_regex

debug: 
	g++ -std=c++11 -DDEBUG -g -fstack-protector-strong monitor.cpp -o monitor.exe -ltins -lboost_regex
