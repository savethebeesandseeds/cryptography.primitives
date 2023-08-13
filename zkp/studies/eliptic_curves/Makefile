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
m_zkp_schnorr_protocol:
	$(GCC) $(HEADERS) \
	./zkp_schnorr_protocol.c $(LINKS) -o ./zkp_schnorr_protocol.o
# --- --- --- --- --- 
zkp_schnorr_protocol:
	make m_zkp_schnorr_protocol
	echo "building [zkp_schnorr_protocol]..."
ifeq ($(ENV),gdb-debug)
	gdb ./zkp_schnorr_protocol.o
else
ifeq ($(ENV),valgrind-debug)
	valgrind --tool=$(VALGRIND_TOOL) ./zkp_schnorr_protocol.o
else
	./zkp_schnorr_protocol.o
endif
endif
# --- --- --- --- --- 