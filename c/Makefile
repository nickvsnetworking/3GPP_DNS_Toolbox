main: main.o naptr.o
	clang main.o naptr.o -lresolv -o main

main.o: main.c naptr.h
	clang -c main.c

naptr.o: naptr.c naptr.h
	clang -c naptr.c

clean:
	rm *.o main
