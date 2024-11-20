#
#    [ISA project] - PCAP NetFlow v5 exporter (p2nprobe)
#    Date: 18.11.2024
#
#    Author: Tomáš Bordák [xborda01]
#

# -D_DEFAULT_SOURCE is for pcap.h library, because it was throwing errors on merlin (unknown types u_int, u_char ..)
#	https://stackoverflow.com/questions/15393905/c-pcap-library-unknown-types-error?noredirect=1
CFLAGS = -Wall -Wextra -std=c99 -D_DEFAULT_SOURCE 
TARGET = p2nprobe

# SOURCE .c FILES #
SRC = main.c common.c export_functions.c flow_functions.c pcap_functions.c 

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