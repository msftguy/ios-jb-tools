OPT_PATH=/sw/bin
BOOST=/Users/msftguy/Downloads/boost_1_44_0
#GCC_45=$(OPT_PATH)/g++-fsf-4.5
BOOST_LIBS=$(BOOST)/stage/lib
all:
	g++ -m64 -o fuzzy_patcher  main.cpp -I$(BOOST) $(BOOST_LIBS)/libboost_program_options.a $(BOOST_LIBS)/libboost_iostreams.a

