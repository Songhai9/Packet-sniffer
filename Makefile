CC = gcc
CFLAGS = -Wall -Wextra -Werror 
LIBS = -lpcap

all: packet_analyzer

packet_analyzer: main.o packet_capture.o packet_analysis.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

main.o: main.c packet_capture.h
	$(CC) $(CFLAGS) -c $<

packet_capture.o: packet_capture.c packet_capture.h
	$(CC) $(CFLAGS) -c $< 

packet_analysis.o: packet_analysis.c packet_analysis.h
	$(CC) $(CFLAGS) -c $< 

clean:
	rm -f *.o packet_analyzer *.txt
