main: main.o naptr.o regex_extensions.o
	clang main.o naptr.o regex_extensions.o -lresolv -o main

main.o: main.c naptr.h
	clang -c main.c

naptr.o: naptr.c naptr.h
	clang -c naptr.c

regex_extensions.o: regex_extensions.c regex_extensions.h
	clang -c regex_extensions.c

clean:
	rm *.o main
