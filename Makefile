# -D_DEFAULT_SOURCE IS FOR PCAP LIBRARY TYPES
CFLAGS = -Wall -Wextra -std=c99 -D_DEFAULT_SOURCE 
TARGET = p2nprobe

# SOURCE .c FILES #
SRC = main.c functions.c pcap_functions.c

# EVERY .c FILE, BUT NOW WITH .o EXTENSION #
OBJ = $(SRC:.c=.o) 

# MAKES EXECUTABLE WITH NAME OF TARGET VARIABLE #
# -lpcap -> this is for linking the program against pcap library #
$(TARGET): $(OBJ)
	gcc $(CFLAGS) -o $(TARGET) $(OBJ) -lpcap

# BUILDS .o #
# $< = FIRST DEPENDENCY - '%.c'  #
%.o: %.c
	gcc $(CFLAGS) -c $< 

# REMOVES EXECUTABLE AND .o FILES #
clean:
	rm -f $(TARGET) $(OBJ)