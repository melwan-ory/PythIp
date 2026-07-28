# 🖧 PythIp [Outil d'analyse et de scan réseau]
## Outil [Python] utilisé pour le scan de réseaux :
- Afficher les ip du réseau
- Exporter les ip (et addresses mac) en csv
- Requête ARP (Nombre de machines qui répondent / Nombre de machines totales)
- Capturer les paquets (Nombre de machines ayant envoyé des paquets + Nombre de paquets interceptés)
- Nom/Os/Ports de l'ordinateur (ciblé par son ip)
- Afficher les reseaux de l'hôte
- Rédiger un "rapport.pdf"

# Installation des paquets
### Linux :

    sudo apt update
    sudo apt install python3 python3-pip libpcap-dev
    pip3 install scapy mac-vendor-lookup reportlab

### Windows :
    
    winget install Python.Python.3.13
    pip install scapy mac-vendor-lookup reportlab

### MacOs :

    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    brew install python
    brew install libpcap
    pip3 install scapy mac-vendor-lookup reportlab

### Vérification :

    python3 --version
    pip3 --version

# Exemple:

    PickData = True #Variable utilisée pour obtenir les données plutôt que de simplement les afficher
    #OsOrdinateur
    test = OsOrdinateur("")
    print(test)
    #NomOrdinateur
    test = NomOrdinateur("")
    print(test)
    #Recherche/AfficherRecherche
    test = AfficherRecherche()
    print(test[0].Ip)
    #Fabriquant
    test = FabricantCarte()
    print(test[0].Ip)
    print(test[0].Fabriquant)
    #Capture
    test = Capture()
    print(test.nMachines)
    print(test.nPaquets)
    #PortsOrdinateurPassif
    test = PortsOrdinateurPassif("")
    print(test[0])
    #PortsOrdinateurAgressif
    test = PortsOrdinateurAgressif("")
    print(test[0])
    #PortsOrdinateurPassifAll
    test = PortsOrdinateurPassifAll()
    for i in range (15):
        print(test[i])
    #PortsOrdinateurAgressifAll
    test = PortsOrdinateurAgressifAll()
    for i in range (45):
       print(test[i])
