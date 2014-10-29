APP=sectsum
SRC=main.c
CFLAGS=-g3 -O0
CLIBS=-lssl -lcrypto -Wall -std=c99 -pedantic

$(APP): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(CLIBS) 

test: $(APP)
	./$(APP) $(APP)

clean:
	$(RM) $(APP)
