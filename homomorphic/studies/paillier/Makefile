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
LINKS := -lcrypto
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
m_paillier_sum:
	$(GCC) $(HEADERS) \
	./paillier_sum.c $(LINKS) -o ./paillier_sum.o
# --- --- --- --- --- 
paillier_sum:
	make m_paillier_sum
	echo "building [paillier_sum]..."
ifeq ($(ENV),gdb-debug)
	gdb ./paillier_sum.o
else
ifeq ($(ENV),valgrind-debug)
	valgrind --tool=$(VALGRIND_TOOL) ./paillier_sum.o
else
	./paillier_sum.o
endif
endif
# --- --- --- --- --- 
m_paillier_sub:
	$(GCC) $(HEADERS) \
	./paillier_sub.c $(LINKS) -o ./paillier_sub.o
# --- --- --- --- --- 
paillier_sub:
	make m_paillier_sub
	echo "building [paillier_sub]..."
ifeq ($(ENV),gdb-debug)
	gdb ./paillier_sub.o
else
ifeq ($(ENV),valgrind-debug)
	valgrind --tool=$(VALGRIND_TOOL) ./paillier_sub.o
else
	./paillier_sub.o
endif
endif
# --- --- --- --- --- 
m_paillier_mul:
	$(GCC) $(HEADERS) \
	./paillier_mul.c $(LINKS) -o ./paillier_mul.o
# --- --- --- --- --- 
paillier_mul:
	make m_paillier_mul
	echo "building [paillier_mul]..."
ifeq ($(ENV),gdb-debug)
	gdb ./paillier_mul.o
else
ifeq ($(ENV),valgrind-debug)
	valgrind --tool=$(VALGRIND_TOOL) ./paillier_mul.o
else
	./paillier_mul.o
endif
endif
# --- --- --- --- --- 
m_paillier_div:
	$(GCC) $(HEADERS) \
	./paillier_div.c $(LINKS) -o ./paillier_div.o
# --- --- --- --- --- 
paillier_div:
	make m_paillier_div
	echo "building [paillier_div]..."
ifeq ($(ENV),gdb-debug)
	gdb ./paillier_div.o
else
ifeq ($(ENV),valgrind-debug)
	valgrind --tool=$(VALGRIND_TOOL) ./paillier_div.o
else
	./paillier_div.o
endif
endif
# --- --- --- --- --- 