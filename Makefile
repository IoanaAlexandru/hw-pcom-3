build: dnsclient
dnsclient: dnsclient.c dnsutils.c parseutils.c dnsclient.h
	gcc -Wall -g dnsclient.c dnsutils.c parseutils.c -o dnsclient
run: dnsclient
	./dnsclient google.com A
clean:
	rm -f dnsclient message.log dns.log
