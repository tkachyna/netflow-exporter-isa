# ISA Projekt - Implementace NetFlow Export
> @autor Tadeáš Kachyňa, xkachy00@stud.fit.vutbr.cz

> @datum 14/11/2022

Zadání projektu bylo vytvoření exportéru NetFlow.

## Spuštění projektu
Spusťtě kompilaci projektu za pomocí Makefile.
```
$ make 
```
Poté můžete server spustit za pomocí následujícího příkazu:
```
$ ./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]
```
kde:

-f je analyzovaný soubor nebo STDIN

-c kolektor na který je výstup posílán, default 127.0.0.1:2055

-a aktivní časovač v sekundách, default 60

-i neaktivní časovač v sekundách, default 10

-m velikost flow cache, default 1024


## Testování

Zapnetě si v okně v druhém okně terminálu kolektor nfcapd, například za pomocí příkazu:
```
$ nfcapd -T all -l . -I any -p 2055
```
Poté spusťte exportér, např. uvedenými příkazy uvedenými na konci tohoto readme.

Kolektor nfcapd exportuje nashromážděné informace pouze jedno za 5 minut.

Po té můžete kolektor vypnout stisknutím CTRL+C.

Výsledné informace si můžete zobrazit za pomocí nástroje nfdump.
```
nfdump -r nfcapd.x
```
kde x je datum ve formátu yymmddhhmm, neboli kdy kolektor zpracoval vaše datové toky.

##  Příklady
```
$ ./flow -f input.pcap -c 192.168.0.1:2055
```
```
$ ./flow -f udp.pcap -c 192.168.0.1:2055 -i 5 
```
```
$ ./flow -m 10 <tcp.pcap
```