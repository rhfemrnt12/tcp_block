LDLIBS=-lpcap

all: tcp_block

tcp_block: main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

main.o: tcp_block.cpp libnet-headers.h
	g++ -c -o main.o tcp_block.cpp -lpcap
clean:
	rm -f tcp_block *.o
