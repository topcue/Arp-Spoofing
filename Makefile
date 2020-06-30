all:Arp-Spoofing

Arp-Spoofing: Arp-Spoofing.o
	gcc -o Arp-Spoofing Arp-Spoofing.o -lpcap
	rm Arp-Spoofing.o

Arp-Spoofing.o: Arp-Spoofing.c
	gcc -c -o Arp-Spoofing.o Arp-Spoofing.c


clean:
	rm *.o Arp-Spoofing
