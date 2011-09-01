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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <sys/time.h>
#include "fmtb.h"

int sock_connect( char * hostname, int port )
{
  struct sockaddr_in sin;
  int sock, i;

  sock = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
  if ( sock < 0 ) {
    perror( "socket()" );
    return( -1 );
  }
  memset( &sin, 0, sizeof(sin) );
  sin.sin_family = AF_INET;
  sin.sin_port = htons( 12345 );

  i = inet_aton( hostname, (struct in_addr *)&sin.sin_addr.s_addr );
  if ( i == 0 ) {
    perror( "inet_aton()" );
    return( -1 );
  }

  i = connect( sock, (struct sockaddr *)&sin, sizeof(sin) );
  if ( i ) {
    perror( "connect()" );
    return( -1 );
  }

  return( sock );
}

/* Interactive shells are more useful ;) */
int interact( int sock )
{
  fd_set fds;
  ssize_t ssize;
  char buffer[1024];

  write( sock, BANNER"\n", sizeof(BANNER) );
  while ( 1 ) {
    FD_ZERO( &fds );
    FD_SET( STDIN_FILENO, &fds );
    FD_SET( sock, &fds );
    select( sock + 1, &fds, NULL, NULL, NULL );

    if ( FD_ISSET(STDIN_FILENO, &fds) ) {
      ssize = read( STDIN_FILENO, buffer, sizeof(buffer) );
      if ( ssize < 0 ) {
	return( -1 );
      }
      if ( ssize == 0 ) {
	return( 0 );
      }
      write( sock, buffer, ssize );
    }

    if ( FD_ISSET(sock, &fds) ) {
      ssize = read( sock, buffer, sizeof(buffer) );
      if ( ssize < 0 ) {
	return(-1);
      }
      if ( ssize == 0 ) {
	return(0);
      }
      write(STDOUT_FILENO, buffer, ssize);
    }
  }
  return( -1 );
}

unsigned long resolve( char * host )
{
  struct hostent * he;
  u_long ret;

  if( !(he = gethostbyname(host)) ) {
    herror( "gethostbyname()" );
    return( -1 );
  }

  memcpy( &ret, he->h_addr, sizeof(he->h_addr) );
  return( ret );
}

