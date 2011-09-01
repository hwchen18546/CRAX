DS = $(PWD)
DB = $(DS)
DO = $(DS)/Objects

FMTB_SRC = fmtb_addr.c  fmtb_builder.c  fmtb_net.c
FMTB_OBJ = $(FMTB_SRC:%.c=$(DO)/%.o)
FMTB_LIB = libfmtb.a

FMT_SRC = expl_fmt.c
FMT_OBJ = $(FMT_SRC:%.c=$(DO)/%.o)
FMT_EXE = expl_fmt

RFMT_SRC = expl_rmt_fmt.c
RFMT_OBJ = $(RFMT_SRC:%.c=$(DO)/%.o)
RFMT_EXE = expl_rmt_fmt

EXE = $(DB)/$(FMT_EXE) $(DB)/$(RFMT_EXE)

LINKER = gcc
LINK_PATH = -L.
LINK_LIB = -lfmtb
LINK = $(LINK_PATH) $(LINK_LIB) 

INC_PATH = -I$(DS)

CC = gcc
CFLAGS = -Wall -pedantic -O2 $(INC_PATH)


all: dirs $(EXE)

dirs : $(DB) $(DO)

$(DB) :
	mkdir $(DB)

$(DO) :
	mkdir $(DO)


$(FMTB_LIB): $(FMTB_OBJ)
	@echo Making Library !
	ar ruv $(FMTB_LIB) $(FMTB_OBJ)
	ranlib $(FMTB_LIB)

$(FMTB_OBJ):  $(DO)/%.o : %.c
	@echo Compiling C Source files
	$(CC) -c $(CFLAGS) $< -o $@



$(FMT_EXE): $(FMT_OBJ)
	@echo Linking $(FMT_EXE)
	$(LINKER)  $(FMT_OBJ) -o $(FMT_EXE) $(LINK)

$(FMT_OBJ):  $(DO)/%.o : %.c
	@echo Compiling C Source files
	$(CC) -c $(CFLAGS) $< -o $@



$(RFMT_EXE): $(RFMT_OBJ)
	@echo Linking $(RFMT_EXE)
	$(LINKER)  $(RFMT_OBJ) -o $(RFMT_EXE) $(LINK)

$(RFMT_OBJ):  $(DO)/%.o : %.c
	@echo Compiling C Source files
	$(CC) -c $(CFLAGS) $< -o $@



$(EXE) : $(FMTB_LIB) $(FMT_EXE) $(RFMT_EXE)
	@echo "*****************************************************************"
	@echo "* libfmtb is for demonstrations only.                           *"
	@echo "* Copyright (C) 2001, 2002 F. Raynal <pappy@miscmag.com>        *"
	@echo "* Copyright (C) 2001, 2002 S. Dralet <zorgon@mastersecurity.fr> *"
	@echo "* All rights reserved.                                          *"
	@echo "*****************************************************************"


clean :
	rm -f $(DO)/*
	rm -f $(FMTB_LIB)
	rm -f $(EXE)
	rm -f $(DS)/*~
