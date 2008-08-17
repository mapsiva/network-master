CC     = gcc
CFLAGS = -ansi -pedantic -Wall -g

XNOOP  = Main
PKG    = PackageHeader
TYPES    = Types
ETH    = Ethernet
TCP     = Tcp
IP    = Ip
UTIL   = Util

HEADERS =  $(PKG).h $(TYPES).h $(ETH).h $(TCP).h $(IP).h $(UTIL).h
OBJECTS = $(PKG).o $(TYPES).o $(ETH).o $(TCP).o $(IP).o $(UTIL).o $(XNOOP).o

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

$(IP).o: $(IP).c $(IP).h
	$(CC) $(CFLAGS) -o $@ -c $<

$(UTIL).o: $(UTIL).c $(UTIL).h
	$(CC) $(CFLAGS) -o $@ -c $<
	
$(XNOOP).o: $(XNOOP).c $(HEADERS)
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	-rm *.o;
