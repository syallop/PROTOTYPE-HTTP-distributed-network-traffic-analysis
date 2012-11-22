CC=g++ -std=gnu++11

All: CaptureManager

CFLAGS = -fpermissive -pthread -Wno-write-strings 
LIBS = -lpcap -ljson -lboost_thread

#general rule - if it's a .cc make an .o
%.o: %.c++
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@ 

SOURCE_FILES = $(wildcard *.c++) $(wildcard ./*/*.c++)
OBJ_FILES = $(SOURCE_FILES:.c++=.o)

CaptureManager: $(OBJ_FILES)
	@echo "linking $@"
	@$(CC) $^ $(LIBS) -o $@

clean:
	@rm -f $(OBJ_FILES)
	@echo "cleaning"
