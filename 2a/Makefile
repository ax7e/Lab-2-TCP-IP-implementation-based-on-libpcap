
all : user

CFLAGS=-Og -g -std=c++11

LIB_FILE=device.cpp packetio.cpp

LIBS=-lpcap -lpthread

%: %.cpp
	g++ -o $@ $^ $(LIB_FILE) $(CFLAGS) $(LIBS)

clean : 
	rm -rf user

test:
	make clean
	make 
	./user
