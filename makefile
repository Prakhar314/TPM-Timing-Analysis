all:
	g++ -c -g proj.cpp -o proj.o -Wall -std=c++17 -I TSS.CPP/Src/ -I TSS.CPP/include/ -L/usr/lib -lcrypto -ldl
	g++ -o proj proj.o TSS.CPP/bin/tssd.a -Wall -std=c++17 -I TSS.CPP/Src/ -I TSS.CPP/include/ -L/usr/lib -lcrypto -ldl
clean:
	rm -rf proj proj.o logs.csv 
	cd TSS.CPP;	make clean