CC     = g++
CFLAGS = -Wall -g -fpack-struct

MAIN		= Main
HTTPD  		= Httpd
THR    		= Thread
UTIL		= Util
SYN         = Syncronize
FLM			= FileManager

HEADERS =  $(THR).h $(HTTPD).h $(UTIL).h $(SYN).h $(FLM).h
OBJECTS = $(THR).o $(HTTPD).o $(UTIL).o $(SYN).o $(FLM).o $(MAIN).o 

# ****************************************************

httpd: $(OBJECTS)
	$(CC) $(CFLAGS) -lpthread -o $@ $^

$(UTIL).o: $(UTIL).cpp $(UTIL).h
	$(CC) $(CFLAGS) -o $@ -c $<

$(HTTPD).o: $(HTTPD).cpp $(HTTPD).h
	$(CC) $(CFLAGS) -o $@ -c $<

$(THR).o: $(THR).cpp $(THR).h
	$(CC) $(CFLAGS) -o $@ -c $<

$(SYN).o: $(SYN).cpp $(SYN).h 
	$(CC) $(CFLAGS) -o $@ -c $<

$(FLM).o: $(FLM).cpp $(FLM).h
	$(CC) $(CFLAGS) -o $@ -c $<
			
$(MAIN).o: $(MAIN).cpp $(HEADERS)
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	-rm *.o;
