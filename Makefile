EXE=main
#CFLAGS=-Wall -Werror -fstack-protector-strong -O2 -Wextra
#CFLAGS=-Wall -Werror -fstack-protector-strong -O0 -ggdb
CFLAGS=-Wall -Werror -fstack-protector-strong -O2 # -fsanitize=address -fsanitize=undefined
#LDFLAGS=-O0 -ggdb
LDFLAGS=-O2 #  -fsanitize=address -fsanitize=undefined
LIBS=-lbsd
OBJ=	aes.o \
	chacha20.o \
	main.o \
	rc4.o

#CFLAGS=-Wall -Wextra -Werror

%.o: %.c %.h
	$(CC) -c -o $@ $< $(CFLAGS)

all: $(EXE)

clean:
	$(RM) -f $(OBJ)

$(EXE): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)


