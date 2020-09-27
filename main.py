#!/usr/bin/env python
import nmap
import os
#
# scaning all services from list
#
def scaningAll(url):
        file = open('result.csv', 'a')
        nm = nmap.PortScanner()
        nm.scan(url, arguments='-sV --script vuln')
        nm.command_line()
        for host in nm.all_hosts():
            dns = nm[host].hostname()
            print(host)
            for protocol in nm[host].all_protocols():
                portList = nm[host][protocol].keys()
                for port in portList:
                    result = ('%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,' % (host, dns, protocol, port, nm[host][protocol][port]['state'], nm[host][protocol][port]['name'], nm[host][protocol][port]['version'], nm[host][protocol][port]['product'], nm[host][protocol][port]['cpe'], nm[host][protocol][port]['conf']))
                    try:
                        vuln = ('"%s"' % nm[host][protocol][port]['script']['vulners'])
                        file.write(result + vuln + '\n')
                        pass
                    except Exception as e:
                        file.write(result + '"vuln not found"\n')
        print('Scann ended.')
        file.close()
#
# reading ip list
#
fs = open('ip_list.txt', 'r')
print('Starting scann...')
print('IP,DNS,Protocolo,Porta,Status,Servico,Versao,Produto,Cpe,Conf,Vuln')
for url in fs:
    url = url.replace('\n', '')
    scaningAll(url)
