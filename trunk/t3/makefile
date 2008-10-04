CC     = g++
CFLAGS = -Wall -g -fpack-struct

HTTP  		= Http
THR    		= Thread
SYN         = Syncronize

HEADERS =  $(THR).h $(SYN).h
OBJECTS = $(THR).o $(SYN).o $(HTTP).o

# ****************************************************

http: $(OBJECTS)
	$(CC) $(CFLAGS) -lpthread -o $@ $^

$(THR).o: $(THR).cpp $(THR).h 
	$(CC) $(CFLAGS) -o $@ -c $<

$(SYN).o: $(SYN).cpp $(SYN).h 
	$(CC) $(CFLAGS) -o $@ -c $<
		
$(HTTP).o: $(HTTP).cpp $(HEADERS)
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	-rm *.o;
