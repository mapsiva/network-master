CC     = gcc
CFLAGS = -ansi -pedantic -Wall -g

XNOOP  = Main
PKG    = PackageHeader
TYPES    = Types
ETH    = Ethernet
TCP     = Tcp
#ETH    = ethernet
#TFH    = tcpdump_file_handler
#PKT    = packet
#OA     = option_analizer
#ICMP   = icmp
#FTR    = filter
#ER     = error
#TI     = type_inverting

HEADERS =  $(PKG).h $(TYPES).h $(ETH).h $(TCP).h
OBJECTS = $(PKG).o $(TYPES).o $(ETH).o $(TCP).o $(XNOOP).o

# ****************************************************

xnoop: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

$(PKG).o: $(PKG).c $(PKG).h
	$(CC) $(CFLAGS) -o $@ -c $<

$(TYPES).o: $(TYPES).c $(TYPES).h
	$(CC) $(CFLAGS) -o $@ -c $<

$(ETH).o: $(ETH).c $(ETH).h
	$(CC) $(CFLAGS) -o $@ -c $<

$(TCP).o: $(TCP).c $(TCP).h
	$(CC) $(CFLAGS) -o $@ -c $<

$(XNOOP).o: $(XNOOP).c $(HEADERS)
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	-rm *.o Network;
