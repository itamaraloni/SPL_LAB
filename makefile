task3: task3.o
	gcc -g -m32 -Wall -o task3 task3.o

task3.o: task3.c
	gcc -g -Wall -m32 -c -o task3.o task3.c

.PHONY: clean
clean:
	rm -rf ./*.o task3