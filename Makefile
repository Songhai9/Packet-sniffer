CC = gcc
CFLAGS = -Wall -Wextra -Werror
LIBS = -lpcap
OBJDIR = obj
BINDIR = bin
SRCDIR = src
INCDIR = include

_OBJS = main.o packet_capture.o ethernet.o ip.o arp.o tcp.o udp.o icmp.o
OBJS = $(patsubst %,$(OBJDIR)/%,$(_OBJS))

all: directories $(BINDIR)/packet_analyzer

directories: $(OBJDIR) $(BINDIR)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/packet_analyzer: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(BINDIR) *.txt

.PHONY: all clean directories
