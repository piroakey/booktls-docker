INCDIR := /opt/openssl/include
LINKDIR := /opt/openssl/lib64
CC := gcc
RM := rm -f
CFLAGS := -W -Wall -O0 -g3 -I. -I$(INCDIR) 
LDFLAGS := -L$(LINKDIR)
LIBS := -lssl -lcrypto

CLIENT_PROG := client
CLIENT_OBJ := common.o client.o

SERVER_PROG := server
SERVER_OBJ := common.o server.o

.c.o:
	$(CC) -c $(CFLAGS) $<

all: $(CLIENT_PROG) $(SERVER_PROG)

$(CLIENT_PROG): $(CLIENT_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

$(SERVER_PROG): $(SERVER_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

clean: 
	$(RM) *.o $(CLIENT_PROG) $(SERVER_PROG)
