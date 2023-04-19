main: main.o naptr.o regex_extensions.o dns_resolvers.o
	clang main.o naptr.o regex_extensions.o dns_resolvers.o -lresolv -o main

main.o: main.c naptr.h
	clang -c main.c

dns_resolvers.o: dns_resolvers.c dns_resolvers.h
	clang -c dns_resolvers.c

naptr.o: naptr.c naptr.h
	clang -c naptr.c

regex_extensions.o: regex_extensions.c regex_extensions.h
	clang -c regex_extensions.c

clean:
	rm *.o main
