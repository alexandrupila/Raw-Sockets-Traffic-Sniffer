# Raw-Sockets-Traffic-Sniffer

18.06

Am facut research legat de sockets si mi-am facut o idee despre ce as vrea sa faca proiectul
Surse raw sockets:
https://www.baeldung.com/cs/raw-sockets
manpage de la socket si citit un pic in header ele din proiect (din netinet)

19.06

Am facut afisarea a catorva tipuri de pachete si a datelor  despre acestea.
La versiunea precedenta mergea doar cu tcp, a trebuit sa schimb parametrii la socket()
iar acum se captureaza frame-uri in loc de pachete; fac decapsularea acestora pentru 
a determina protocolul

20.06

Am adaugat niste monitorizare pentru icmp, detecteaza daca vin prea multe pachete de 
la o anumita adresa ip si alerteaza in cazul acesta. 

21.06

Am adaugat abilitatea de a filtra dupa ip si port si incerc sa fac astfel incat sa imi
afiseze DNS-urile capturate. Am cautat niste librarii pe net ca sa ma ajute cu structurile acelea

De aici am luat structura din utils.h: https://github.com/seladb/PcapPlusPlus

22.06

Am implementat afisarea traficului de ARP si celui de IGMP. Am luat structurile din acelasi loc din care
am luat pentru dns.

23.06

Am implementat functie de data dump pentru a-mi afisa datele efective venite in hexa si in clar ceea ce se poate citi.
De asemenea am reusit sa fac filtrarea dupa port

24.06

Am facut procesarea DNS-urilor si afisarea acestora si am mai adaugat --help pentru a vedea filtrele disponibile.
In principiu am cam terminat.