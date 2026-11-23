CFLAGS = -fno-stack-protector -no-pie -fcf-protection=none
all: vuln
vuln: vuln.c
	gcc $(CFLAGS) -o vuln vuln.c
run: vuln
	python3 exploit.py
debug: vuln
	gdb ./vuln
clean:
	rm -f vuln
