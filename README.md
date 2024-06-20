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