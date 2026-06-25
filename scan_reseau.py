from scapy.all import ARP, Ether, srp, sniff, IP, ICMP, conf, sr1, TCP, sr
from collections import Counter
import socket

#AfficherIp
from mac_vendor_lookup import MacLookup

reseau = "192.168.1.0/24"
resultats = ""
reponses_paquets = "Veuillez lancer une 'Réponse Machine' pour obtenir cette donnée"
PickData = False

class RecuPsrcHwsr:
    def __init__(self, Psrc, Hwsr):
        self.Ip = Psrc
        self.Mac = Hwsr    
class RecuPsrcHwsrFabriquant:
    def __init__(self, Psrc, Hwsr, Fabriquant):
        self.Ip = Psrc
        self.Mac = Hwsr
        self.Fabriquant = Fabriquant
class CaptureReseau:
    def __init__(self, nMachines, nPaquets):
        self.nMachines = nMachines #Nombre de machines
        self.nPaquets = nPaquets  #Nombre de paquets
class ARPPaquets:
    def __init__(self, reponses, non_reponses):
        self.reponses = reponses #Nombre de réponses
        self.non_reponses = non_reponses

def Reseau():
    global reseau
    temp = input("Réseau (192.168.1.0/24 par défaut) : ")
    if temp=="":
        reseau = "192.168.1.0/24"
    else:
        reseau = temp
    Recherche()

def AfficherReseau():
    print("Réseau : " + reseau)
    Choix()

def ExportCSV():
    import csv
    import ipaddress

    # Tri des résultats par adresse IP
    resultats_tries = sorted(
        resultats,
        key=lambda x: ipaddress.ip_address(x[1].psrc)
    )   

    with open("machines.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Nom", "Adresse IP", "Adresse MAC", "Os"])

        global PickData
        PickData = True
        for _, recu in resultats_tries:
            writer.writerow([NomOrdinateur(recu.psrc), recu.psrc, recu.hwsrc, OsOrdinateur(recu.psrc)])
        PickData = False

    print("Export CSV effectué.")
    Choix()

def Requête_ARP(): #Maj v1
    paquet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=reseau)
    reponses, non_reponses = srp(paquet, timeout=2, verbose=False)
    global reponses_paquets
    reponses_paquets = reponses
    if PickData==True:
        data=ARPPaquets(str(len(reponses)), str(len(non_reponses)))
        return data
    else:
        print(f"Paquets envoyés : {len(reponses) + len(non_reponses)}")
        print(f"Réponses reçues : {len(reponses)}")
        print(f"Sans réponse : {len(non_reponses)}")
    Choix()

def Capture(): #Maj v1
    DUREE = int(input("Durée de capture (s) : "))

    compteur = Counter()

    def analyser(paquet):
        if IP in paquet:
            compteur[paquet[IP].src] += 1
    
    if PickData==True:
        sniff(filter="ip",prn=analyser,timeout=DUREE,store=False)
        data=CaptureReseau(str(len(compteur)), str(sum(compteur.values())))
        return data
    else:
        print(f"\nCapture en cours pendant {DUREE} secondes...")

        sniff(filter="ip",prn=analyser,timeout=DUREE,store=False)

        print("\n===== Résultat =====")
        print("Adresse IP\t\tPaquets")

        for ip, nb in compteur.most_common():
            print(f"{ip:<15}\t{nb}")

        print(f"\nNombre de machines : {len(compteur)}")
        print(f"Nombre total de paquets : {sum(compteur.values())}")
    Choix()

def Recherche():
    global resultats
    requete_arp = ARP(pdst=reseau)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquet = broadcast / requete_arp #Permet d'empiler des couches de protocoles
    resultats = srp(paquet, timeout=2, verbose=False)[0]  #Send and Receive Packets at Layer 2. timeout=2 : attend au maximum 2 secondes les réponses. verbose=False : n'affiche pas les détails. 
    if PickData == False :
        Choix()

def AfficherIp(cx): #Maj v2
    if cx=="":
            cx=input("Afficher les fabriquants ? (O - N) : ")

    data=[]
    for _, recu in resultats:
        try:
            fabricant = MacLookup().lookup(recu.hwsrc)
        except:
             fabricant = "Inconnu"
        
        if cx=="O" or cx=="o" or cx=="Y" or cx=="y":
            if PickData==True:
                data.append(RecuPsrcHwsrFabriquant(str(recu.psrc), str(recu.hwsrc), fabricant))
            else:
                print(f"{recu.psrc} - {recu.hwsrc} - {fabricant}")
        if cx=="N" or cx=="n":
            if PickData==True:
                data.append(RecuPsrcHwsr(str(recu.psrc), str(recu.hwsrc)))
            else:
                print(f"{recu.psrc} - {recu.hwsrc}")

    if PickData==True:
        return data        
    Choix()

def NomOrdinateur(ip):
    if ip == "":
        ip = input("Adresse IP : ")

    try:
        nom_pc = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        nom_pc = "Inconnu"

    if PickData:
        return nom_pc
    else:
        print(f"Nom du PC : {nom_pc}")
        Choix()

def OsOrdinateur(ip): #Maj v2
    if ip=="":
        ip = input("Adresse IP : ")

    reponse = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=False)

    if reponse:
        ttl = reponse.ttl

        if ttl <= 64:
            if PickData==True:
                return "OS probable : Linux / macOS"
            print("OS probable : Linux / macOS")
        elif ttl <= 128:
            if PickData==True:
                return "OS probable : Windows"
            print("OS probable : Windows")
        elif ttl <= 255:
            if PickData==True:
                return "OS probable : Équipement réseau (Cisco, etc.)"
            print("OS probable : Équipement réseau (Cisco, etc.)")
        else:
            if PickData==True:
                return "Aucune réponse"
            print("Aucune réponse")

        if PickData==False:
            print(f"TTL = {ttl}")
            Choix()

def PortsOrdinateur():
    cx=input("Découverte Passive/courte(1) ou Agressive/longue(2) : ")
    if cx=="1" or cx=="Passive":
        PortsOrdinateurPassif("")
    if cx=="2" or cx=="Agressive":
        PortsOrdinateurAgressif("")
def PortsOrdinateurPassif(ip): #Maj v2
    if ip=="":
        ip = input("Adresse IP ('All' pour toutes) : ")

    ports = [21, 22, 23, 25, 110, 143,53, 67, 68, 69, 135, 137, 138, 139, 445,80, 443, 8080, 8443, 161, 162, 389, 636, 1433, 1521, 3306, 5432, 6379, 27017, 3389, 5900,5000, 5601, 8000, 8888, 9200]

    if PickData==False:
        print("Scan en cours...")

    if ip=="All":
        prefix = reseau.rsplit(".", 1)[0] + "."
        for i in range(1, 255):
            ip = prefix + str(i)

            # Vérifie si l'hôte répond en ARP
            arp = ARP(pdst=ip)
            rep, _ = sr(arp, timeout=1, verbose=False)

            if not rep:
                continue

            # Scan des ports
            paquets = IP(dst=ip) / TCP(dport=ports, flags="S")
            reponses, _ = sr(paquets, timeout=0.5, verbose=False)

            ouverts = []

            for _, r in reponses:
                if r.haslayer(TCP) and r[TCP].flags == 0x12:
                    ouverts.append(r[TCP].sport)

            if PickData==True:
                if ouverts:
                    for port in ouverts:
                        data.append(port)
                data.append("|") #Séparateur entre les ip
            else:
                if ouverts:
                    print(f"\nIP : {ip}")
                    print("Ports ouverts :")
                    for port in ouverts:
                        print(f"  Port {port}")
    else:
        paquets = IP(dst=ip) / TCP(dport=ports, flags="S")
        reponses, _ = sr(paquets, timeout=2, verbose=False)

        if PickData==True:
            data=[]
            for _, rep in reponses:
                if rep.haslayer(TCP) and rep[TCP].flags == 0x12:  # SYN-ACK
                    data.append(str(rep[TCP].sport))
            return data
        else:
            print("\nPorts ouverts :")

            for _, rep in reponses:
                if rep.haslayer(TCP) and rep[TCP].flags == 0x12:  # SYN-ACK
                    print(f"Port {rep[TCP].sport} : OUVERT")

    Choix()
def PortsOrdinateurAgressif(ip): #Maj v2
    if ip=="":
        ip = input("Adresse IP ('All' pour toutes) : ")
        
    if PickData==False:
        print("Scan en cours...")

    if ip=="All":
        prefix = reseau.rsplit(".", 1)[0] + "."

        data = []

        for i in range(1, 255):

            ip = f"{prefix}{i}"

            # Vérifie que la machine existe
            rep, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                timeout=1,
                verbose=False
            )

            if not rep:
                continue

            print(f"Scan de {ip}...")

            reponses, _ = sr(
                IP(dst=ip) / TCP(dport=range(65536), flags="S"),
                timeout=2,
                verbose=False
            )

            ports_ouverts = []

            for _, r in reponses:
                if r.haslayer(TCP) and r[TCP].flags == 0x12:
                    ports_ouverts.append(r[TCP].sport)

            if PickData==True:
                for port in sorted(ports_ouverts):
                    data.append(port)
                data.append("|") #Séparateur entre les ip
            else:
                print(f"IP : {ip}")
                print(f"{len(ports_ouverts)} port(s) ouvert(s) :")
                for port in sorted(ports_ouverts):
                    print(port)

        if PickData==True:
            return data
    else:
        reponses, _ = sr(
            IP(dst=ip) / TCP(dport=range(0, 65536), flags="S"),
            timeout=2,
            verbose=False
        )

        if PickData==True:
            ports_ouverts = []
            for _, rep in reponses:
                if rep.haslayer(TCP) and rep[TCP].flags == 0x12:  # SYN-ACK
                    ports_ouverts.append(rep[TCP].sport) #Sport : Réponse du port appelé
            return ports_ouverts
        else:
            ports_ouverts = []
            for _, rep in reponses:
                if rep.haslayer(TCP) and rep[TCP].flags == 0x12:  # SYN-ACK
                    ports_ouverts.append(rep[TCP].sport)
            print(f"\n{len(ports_ouverts)} port(s) ouvert(s) :")
            for port in sorted(ports_ouverts):
                print(port)

    Choix()

def AfficherReseauxHote():
    print(conf.route)
    Choix()

def CreationPDF():
    print("Cela peut prendre quelques minutes.")
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        PageBreak
    )
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.units import cm
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from collections import Counter
    from datetime import datetime
    import socket

    global PickData
    PickData = True

    styles = getSampleStyleSheet()

    titre = styles["Title"]
    titre.alignment = TA_CENTER

    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    normal = styles["BodyText"]

    doc = SimpleDocTemplate(
        "rapport.pdf",
        rightMargin=1.5*cm,
        leftMargin=1.5*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )

    story = []
    # PAGE DE GARDE
    story.append(Spacer(1,3*cm))
    story.append(Paragraph("RAPPORT D'ANALYSE RÉSEAU", titre))
    story.append(Spacer(1,1*cm))

    # RESUME
    story.append(Paragraph("Résumé", h1))
    story.append(Spacer(1,0.3*cm))
    resume = [
        ["Information","Valeur"],
        ["Réseau analysé", reseau],
        ["Machines détectées", str(len(resultats))],
        ["Date", datetime.now().strftime("%d/%m/%Y %H:%M")]
    ]
    tableau = Table(resume,colWidths=[7*cm,8*cm])
    tableau.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.darkblue),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('GRID',(0,0),(-1,-1),0.5,colors.black),
        ('BACKGROUND',(0,1),(-1,-1),colors.beige),
        ('BOTTOMPADDING',(0,0),(-1,0),8)
    ]))
    story.append(tableau)
    story.append(Spacer(1,0.8*cm))

    # DETAILS DES MACHINES
    story.append(Paragraph("Détails des machines", h1))
    story.append(Spacer(1, 0.5 * cm))

    IpMac = AfficherIp("O")
    Constructeur = AfficherIp("O")

    for i in range(len(IpMac)):
        Nom = NomOrdinateur(IpMac[i].Ip)
        Os = OsOrdinateur(IpMac[i].Ip)
        Ports = PortsOrdinateurPassif(IpMac[i].Ip)

        story.append(Paragraph(f"<b>{IpMac[i].Ip}</b>", h2))

        infos = [
            ["Adresse MAC", IpMac[i].Mac],
            ["Constructeur", Constructeur[i].Fabriquant],
            ["Nom DNS", Nom],
            ["OS probable", Os],
            ["Ports ouverts", ", ".join(map(str, Ports))]
        ]

        t = Table(infos, colWidths=[4 * cm, 11 * cm])
        t.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('FONTNAME', (0, 0), (0, -1), "Helvetica-Bold"),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6)
        ]))
        story.append(t)
        story.append(Spacer(1, 0.5 * cm))

    story.append(PageBreak())

    # STATISTIQUES
    story.append(Paragraph("Statistiques",h1))

    compteur = Counter(c.Fabriquant for c in Constructeur)
    data = [["Constructeur","Nombre"]]
    for constructeur, nb in compteur.items():
        data.append([constructeur, str(nb)])

    tab = Table(data,colWidths=[10*cm,4*cm])
    tab.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.darkblue),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('GRID',(0,0),(-1,-1),0.5,colors.black),
        ('BACKGROUND',(0,1),(-1,-1),colors.beige),
        ('FONTNAME',(0,0),(-1,0),"Helvetica-Bold")
    ]))
    story.append(tab)

    story.append(Spacer(1,0.7*cm))

    # CONCLUSION
    story.append(Paragraph("Conclusion",h1))
    
    texte = f"""Le rapport présente les informations découvertes à l'aide de requêtes ARP, ICMP et TCP SYN. Les services détectés doivent être vérifiés afin de confirmer qu'ils correspondent aux besoins de l'infrastructure et qu'aucun service inutile n'est exposé."""
    story.append(Paragraph(texte,normal))

    doc.build(story)
    print("Rapport PDF créé avec succès.")

    PickData = False
    Choix()

def Choix():
    print(f"\nParamètres :")
    print(f"  0- Quitter")
    print(f"  1- Changer de réseau")
    print(f"  2- Afficher le réseau")
    print(f"  3- Afficher les ip")
    print(f"  4- Exporter les ip en csv")
    print(f"  5- Requête ARP")
    print(f"  6- Capturer les paquets")
    print(f"  7- Nom de l'ordinateur")
    print(f"  8- Os de l'ordinateur")
    print(f"  9- Ports de l'ordinateur")
    print(f"  10- Afficher les reseaux de l'hôte")
    print(f"  11- Rédiger le rapport.pdf")

    cx=input(f"\nChoix : ")

    if cx=="1":
        Reseau()
    if cx=="2":
        AfficherReseau()
    if cx=="3":
        AfficherIp("")
    if cx=="4":
        ExportCSV()
    if cx=="5":
        Requête_ARP()
    if cx=="6":
        Capture()
    if cx=="7":
        NomOrdinateur()
    if cx=="8":
        OsOrdinateur("")
    if cx=="9":
        PortsOrdinateur()
    if cx=="10":
        AfficherReseauxHote()
    if cx=="11":
        CreationPDF()

Reseau() #Lancement du programme
