int main( int argc, char * argv[] ) 
{
	char buffer[1024];

  	snprintf( buffer, sizeof(buffer), "XXXXXXX%s", argv[1] );
  	printf( buffer );
}
