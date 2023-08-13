# --- --- --- --- --- 
ENV := gdb-debug
ENV := valgrind-debug
ENV := no-debug
# --- --- --- --- --- 
VALGRIND_TOOL=helgrind
VALGRIND_TOOL=memcheck --leak-check=full --show-leak-kinds=all
VALGRIND_TOOL=memcheck --track-origins=yes --leak-check=full --show-leak-kinds=all --track-fds=yes -s
VALGRIND_TOOL=memcheck --track-origins=yes --leak-check=full --track-fds=yes -s
# --- --- --- --- --- 
STATIC_FLAGS := -static # enable static
STATIC_FLAGS := # disable static
DISABLE_WARNINGS := -Wno-unused-function
LINKS := -lm
# --- --- --- --- --- 
GCC := gcc
# --- --- --- --- --- 
ifeq ($(ENV),gdb-debug)
GCC += -Wall -g -O0 $(DISABLE_WARNINGS) $(STATIC_FLAGS) 
else
ifeq ($(ENV),valgrind-debug)
GCC += -Wall -g -O0 $(DISABLE_WARNINGS) $(STATIC_FLAGS) 
else
GCC += -Wall $(DISABLE_WARNINGS) $(STATIC_FLAGS) 
endif
endif
HEADERS := 
# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- 
clean:
	rm -f ./*.o
	rm -rf ./vgcore.*
# --- --- --- --- --- 
m_1d_DCT:
	$(GCC) $(HEADERS) \
	./1d_DCT.c $(LINKS) -o ./1d_DCT.o
# --- --- --- --- --- 
1d_DCT:
	make m_1d_DCT
	echo "building [1d_DCT]..."
ifeq ($(ENV),gdb-debug)
	gdb ./1d_DCT.o
else
ifeq ($(ENV),valgrind-debug)
	valgrind --tool=$(VALGRIND_TOOL) ./1d_DCT.o
else
	./1d_DCT.o
endif
endif
# --- --- --- --- --- 
m_2d_DCT:
	$(GCC) $(HEADERS) \
	./2d_DCT.c $(LINKS) -o ./2d_DCT.o
# --- --- --- --- --- 
2d_DCT:
	make m_2d_DCT
	echo "building [2d_DCT]..."
ifeq ($(ENV),gdb-debug)
	gdb ./2d_DCT.o
else
ifeq ($(ENV),valgrind-debug)
	valgrind --tool=$(VALGRIND_TOOL) ./2d_DCT.o
else
	./2d_DCT.o
endif
endif
# --- --- --- --- --- 