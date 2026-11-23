CFLAGS = -no-pie -fcf-protection=none
all: vuln heap_demo
vuln: vuln.c
	gcc $(CFLAGS) -o vuln vuln.c
heap_demo: heap_demo.c
	gcc $(CFLAGS) -g -o heap_demo heap_demo.c
run: vuln
	python3 exploit.py
debug: heap_demo
	gdb -x debug.gdb ./heap_demo
clean:
	rm -f vuln heap_demo
