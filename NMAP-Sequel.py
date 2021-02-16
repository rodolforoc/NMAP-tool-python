import nmap
from pprint import pprint

while True:
    print("""\nOque você deseja fazer?\n
                1 - Obter informações detalhadas sobre o dispositivo
                2 - Escanear portas abertas na rede
                e - Sair da aplicação""")

    user_input = input("\nDigite sua opção: ")

    if user_input == "1":
        # Inicializando o port scanner
        mynmap = nmap.PortScanner()

        ip = input("\nEntre com o endereço de IP para o Scan: ")

        print("\nIsso pode levar alguns minutos...\n")

        # Scan no dispositivo
        scan = mynmap.scan(ip, '1-1024', '-v -sS -sV -O -A -e ens3')

        # Traduzindo informações a partir do resultado
        print("\n= = = = = = = HOST {} = = = = = = =".format(ip))

        print("\n\nInformações Gerais")

        #MAC address
        try:
            mac = scan['scan'][ip]['addresses']['mac']
            print("\n-> MAC address: {}".format(mac))
        except KeyError:
            pass

        # Sistema Operacional
        os = scan['scan'][ip]['osmatch'][0]['name']
        print("-> Sistema Operacional: {}".format(os))

        # Tempo de atividade do dispositivo
        uptime = scan['scan'][ip]['uptime']['lastboot']
        print("-> Tempo de atividade do dispositivo: {}".format(uptime))

        # Portas
        print("\n\nPORTAS\n")

        for port in list(scan['scan'][ip]['tcp'].items()):
            print("-> {} | {} | {}".format(port[0], port[1]['name'], port[1]['state']))

        print("\n\nOutras informações\n")

        # comando NMAP usado para o scan
        print("-> comando NMAP: {}".format(scan['nmap']['command_line']))

        # versão NMAP
        version = str(mynmap.nmap_version()[0]) + "." + str(mynmap.nmap_version()[1])
        print("-> versão NMAP: {}".format(version))

        # Tempo decorrido
        print("-> Tempo decorrido: {}".format(scan['nmap']['scanstats']['elapsed'] + "segundos"))

        # Tempo de scan
        print("-> Tempo do scan: {}".format(scan['nmap']['scanstats']['timestr']))
        print("\n\n")

        continue

    elif user_input == "2":
        mynmap = nmap.PortScanner()

        print("\nIsso pode levar alguns minutos...\n")

        # Scaneando o dispositivo
        scan = mynmap.scan(ports = '1-1024', arguments = '-sS -e ens3 -iL /home/osboxes/Apps/ip.txt')

        for device in scan['scan']:
            print("\nPortas abertas em {}:".format(device))
            for port in scan['scan'][device]['tcp'].items():
                if port[1]['state'] == 'open':
                    print("-->" + str(port[0]) + "|" + port[1]['name'])

        continue

    elif user_input == "e":
        print('\nSaindo da aplicação...\n')

		break

    else:
        print("\nOpção inválida. Tente noamente!\n")

        continue
