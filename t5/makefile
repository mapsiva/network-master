CC     = gcc
CFLAGS = -Wall -g -fpack-struct

SUBNET 		= Subnet
XNOOP  		= Xnoop
PKG    		= PackageHeader
TYPES    	= Types
ETH    		= Ethernet
TCP     	= Tcp
IP    		= Ip
UTIL   		= Util
UDP     	= Udp
ICMP    	= Icmp
ARP     	= Arp
STACK   	= Stack
AN   		= Analyzer
FIL   		= Filter
RIP         = Rip

HEADERS =  $(PKG).h $(TYPES).h $(ETH).h $(TCP).h $(IP).h $(UTIL).h $(UDP).h $(ICMP).h $(ARP).h $(STACK).h $(AN).h $(FIL).h $(RIP).h $(XNOOP).h 
OBJECTS =  $(PKG).o $(TYPES).o $(ETH).o $(TCP).o $(IP).o $(UTIL).o $(UDP).o $(ICMP).o $(ARP).o $(STACK).o $(AN).o $(FIL).o $(RIP).o $(XNOOP).o $(SUBNET).o

# ****************************************************

subnet: $(OBJECTS)
	$(CC) $(CFLAGS) -lpthread -o $@ $^ 
	
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
	
$(UDP).o: $(UDP).c $(UDP).h
	$(CC) $(CFLAGS) -o $@ -c $<

$(ICMP).o: $(ICMP).c $(ICMP).h
	$(CC) $(CFLAGS) -o $@ -c $<

$(ARP).o: $(ARP).c $(ARP).h
	$(CC) $(CFLAGS) -o $@ -c $<
	
$(STACK).o: $(STACK).c $(STACK).h
	$(CC) $(CFLAGS) -o $@ -c $<	
	
$(AN).o: $(AN).c $(AN).h
	$(CC) $(CFLAGS) -o $@ -c $<

$(FIL).o: $(FIL).c $(FIL).h
	$(CC) $(CFLAGS) -o $@ -c $<

$(RIP).o: $(RIP).c $(RIP).h
	$(CC) $(CFLAGS) -o $@ -c $<
	
$(XNOOP).o: $(XNOOP).c $(XNOOP).h
	$(CC) $(CFLAGS) -o $@ -c $<

$(SUBNET).o: $(SUBNET).c $(HEADERS)
	$(CC) $(CFLAGS)  -o $@ -c $< 

clean:
	-rm *.o;
