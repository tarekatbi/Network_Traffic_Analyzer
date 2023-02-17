import os
dest = open("dest.txt", "w")
visualisateur = open("visualisateur.puml","w")
visualisateur.write("@startuml""\n")
visualisateur2 = open("visualisateur_filtre.puml", "w")
visualisateur2.write("@startuml""\n")
def convertHexToDec(hexSubString):
    return chr(int(hexSubString, 16))  # conversion de l'hex en decimal !
def fic_to_liste(file):  # Lecture ligne par ligne du fichier
    l = []
    for i in file:
        l.append(i)
    return l
def enlever_espace(liste):
    l = []
    for i in liste:
        l.append(i.replace(" ", ""))
    return l
def enlever_saut(liste):
    l = []
    for i in liste:
        l.append(i.replace("\n", ""))
    return l
def skip_offset(l_originale):
    l = []
    for i in l_originale:
        l.append(i[7:54])
    return l
def binary(num, length=16):
    return format(num, '#0{}b'.format(length + 2))

unique = False

def ouverture(fich_name):
    a = fic_to_liste(fich_name)
    b = skip_offset(a)
    b = enlever_espace(b)
    b = enlever_saut(b)
    b = b + ['']
    d = ''
    trame1 = b[0:b.index(d)]
    str = "".join(trame1)
    fichier = open("transition.txt", "w")
    fichier.write(str)
    fichier.write("\n")
    i=0
    while i < len(b):
        if b[i] == '':
            del b[0:b.index(d)+1]
            if len(b) != 0:
                c = b[0:b.index(d)]
                str = "".join(c)
                fichier.write(str + "\n")
                i = 0
        else:
            i += 1

def analyse(fich_name):
    f = open(fich_name, "r")
    lines = f.readlines()
    lignes = lines
    for i in range(len(lines)):
        dest.write("__________________________________________TRAME "+str(i+1)+"_________________________________________\n")
        dest.write("_________________________________________ " +str((len(lignes[i])-1)/2)+" octets ____________________________________\n")
        x = lines[i].replace("\n", "")
        y = "".join(x)
        dest.write("__________________________________________Ethernet________________________________________\n")
        mac = ""
        mac2 = ""
        mac_dest = y[0:12]
        mac_src = y[12:24]
        for j in range(0, 12, 2):
            if j != 10:
                mac += mac_dest[j] + mac_dest[j + 1]
                mac += ":"
            else:
                mac += mac_dest[j] + mac_dest[j + 1]
        mac_dest = mac
        dest.write("L'Adresse MAC Destination est : " + mac_dest + "\n")
        for j in range(0, 12, 2):
            if i != 10:
                mac2 += mac_src[j] + mac_src[j + 1]
                mac2 += ":"
            else:
                mac2 += mac_src[j] + mac_src[j + 1]
        mac_src = mac2
        dest.write("L'Adresse MAC Source est : " + mac_src + "\n")
        type = y[24:28]
        Types = {"0800": "IPv4", "86dd": "Ipv6", "0805": "X.25", "0806": "ARP", "8035": "RARP"}
        if type in Types:
            dest.write("Le Protocole encapsulé est : " + Types[type] + "\n\n")
        else:
            dest.write("Le Protocole encapsulé est : Inconnue\n\n")


        dest.write("__________________________________________IP_____________________________________________\n")
        a = y[29]
        dest.write("IHL : 0x" + a + "\n")
        if a == "5":
            dest.write("L'entete IP ne contient pas d'option\n")
        else:
            option = int(a, base=16)
            dest.write("L'entete IP contient " + str(option * 4) + " octets donc " + str(
                option * 4 - 20) + " octets d'options\n")
            option_ip = (option * 4 - 20) * 2
        b = y[30:32]
        dest.write("TOS : " + str(int(b, base=16)) + "\n")
        c = y[32:36]
        dest.write("TOTAL LENGTH : " + str(int(c, base=16)) + "\n")
        e = y[36:40]
        dest.write("IDENTIFICATION : " + str(int(e, base=16)) + "\n")
        p = y[40:44]
        q = int(p, base=16)
        a = format(q)
        z = binary(q)
        t = str(z)
        R = t[2]
        DF = t[3]
        MF = t[4]
        OFFSET = t[5:18]
        dest.write("Flags : ")
        dest.write("R = " + R + " " + "DF = " + DF + " " + "MF = " + MF + "\n")
        dest.write("Offset : " + str(int(OFFSET, base=16)) + "\n")

        g = y[44:46]
        dest.write("TTL : " + str(int(g, base=16)) + "\n")
        d = y[46:48]
        if d == "01":
            dest.write("Protocol encapsulé : ICMP\n")
            prot = "ICMP"
        if d == "06":
            dest.write("Protocol encapsulé : TCP\n")
            prot = "TCP"
        if d == "11":
            dest.write("Protocol encapsulé : UDP\n")
            prot = "UDP"
        if d == "02":
            print("Protocol: IGMP")
        if d == "08":
            print("Protocol: EGP")
        if d == "09":
            print("Protocol: IGP")
        if d == "24":
            print("Protocol: XTP")
        if d == "2E":
            print("Protocol: RSVP")
        ij = y[48:52]
        dest.write("HEADER CHECKSUM : " + ij + "\n")
        l = str(int(y[52:54], base=16)) + "." + str(int(y[54:56], base=16)) + "." + str(
            int(y[56:58], base=16)) + "." + str(int(y[58:60], base=16))
        m = str(int(y[60:62], base=16)) + "." + str(int(y[62:64], base=16)) + "." + str(
            int(y[64:66], base=16)) + "." + str(int(y[66:68], base=16))
        dest.write("Adresse IP Source : " + l + "\n")
        dest.write("Adresse IP Destination : " + m + "\n\n")


        dest.write("__________________________________________"+prot+"_____________________________________________\n")
        if prot == "TCP":
           a2 = y[29]
           if a2 == "5":
               b2 = y[68:72]
               dest.write("Port Source : " + str(int(b2, base=16)) + "\n")
               c2 = y[72:76]
               dest.write("Port Destination : " + str(int(c2, base=16)) + "\n")
               d2 = y[76:84]
               dest.write("Sequence Number : " + str(int(d2, base=16)) + "\n")
               e2 = y[84:92]
               dest.write("ACK Number : " + str(int(e2, base=16)) + "\n")
               f2 = y[92]
               if f2 == "5":
                   dest.write("THL : 0x" + f2 + "\n")
                   dest.write("L'entete TCP ne contient pas d'option\n")

               else:
                   dest.write("THL : 0x" + f2 + "\n")
                   option2 = int(f2, base=16)
                   dest.write("L'entete TCP contient " + str(option2 * 4) + " octets donc " + str(
                       option2 * 4 - 20) + " octets d'options\n")
               r_flags = y[93:96]
               r_flags = int(r_flags, base=16)
               aa = format(r_flags)
               zz = binary(r_flags)
               tt = str(zz)
               Reserved = tt[6:11]
               URG = tt[12]
               ACK = tt[13]
               PSH = tt[14]
               RST = tt[15]
               SYN = tt[16]
               FIN = tt[17]
               dest.write("Reserved : " + str(int(Reserved, base=16)) + "\n")
               dest.write("Flags : ")
               dest.write(
                   "URG : " + URG + " ACK : " + ACK + " PSH : " + PSH + " RST : " + RST + " SYN : " + SYN + " FIN : " + FIN + "\n")
               g2 = y[96:100]
               dest.write("Window : " + g2 + "\n")
               h2 = y[100:104]
               dest.write("Checksum : " + h2 + "\n")
               k2 = y[104:108]
               dest.write("Urgent Pointer : " + k2 + "\n")
               if f2 == "5":
                   http = y[108:]
                   methode = y[108:116]

                   Methodes = {"47455420", "504f5354", "48454144", "50555420",
                               "48545450"}
                   if methode in Methodes:
                       dest.write(
                           "__________________________________________HTTP + DATA_____________________________________________\n")
                       output2 = ''
                       count2 = 1
                       for k in http[::1]:
                           if count2 % 4 == 0:
                               output2 = output2 + k + '.'
                               count2 = 0
                           else:
                               output2 = output2 + k
                           count2 += 1
                       http2 = output2[::1]
                       http2 = http2.split(".")
                       elementSupprime = http2.pop()
                       d = "0d0a"
                       for i in http2:
                           if i == d:
                               ss = ""
                               entete = http2[0:http2.index(d) + 1]
                               entete = "".join(entete)
                       if len(entete) % 2 == 0:
                           for i in range(0, len(entete), 2):
                               sub = entete[i] + entete[i + 1]
                               ss += convertHexToDec(sub)
                       dest.write(ss + "\n")
                       visualisateur.write("note left of " + l + "\n")
                       visualisateur.write(str(int(b2, base=16)) + "\n")
                       visualisateur.write("end note""\n")
                       visualisateur.write(l+"__>"+m+":"+ss+"\n")
                       visualisateur.write("note left of " + m + "\n")
                       visualisateur.write(str(int(c2, base=16)) + "\n")
                       visualisateur.write("end note""\n")

                   else:
                       visualisateur.write("note left of " + l + "\n")
                       visualisateur.write(str(int(b2, base=16)) + "\n")
                       visualisateur.write("end note""\n")
                       if (SYN == "0") and (ACK == "1"):
                           visualisateur.write(
                           l + "-->" + m + ":""TCP->" "[ACK]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                               int(e2, base=16)) + ' '"WIN=" + str(int(g2, base=16)) +"\n")
                       if (SYN == "1") and (ACK == "0"):
                           visualisateur.write(
                           l + "-->" + m + ":""TCP->" "[SYN]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                               int(e2, base=16)) + ' '"WIN=" + str(int(g2, base=16)) +
                                "\n")
                       if (SYN == "1") and (ACK == "1"):
                           visualisateur.write(
                           l + "-->" + m + ":""TCP->" "[SYN/ACK]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                               int(e2, base=16)) + ' '"WIN="' ' + str(int(g2, base=16)) + "\n")
                       if (FIN == "1") and (ACK == "0"):
                           visualisateur.write(
                           l + "-->" + m + ":""TCP->" "[FIN]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                               int(e2, base=16)) + ' '"WIN="' ' + str(int(g2, base=16)) + "\n")
                       if (FIN == "1") and (ACK == "1"):
                           visualisateur.write(
                           l + "-->" + m + ":""TCP->" "[FIN/ACK]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                               int(e2, base=16)) + ' '"WIN="' ' + str(int(g2, base=16)) + "\n")
                       visualisateur.write("note left of " + m + "\n")
                       visualisateur.write(str(int(c2, base=16)) + "\n")
                       visualisateur.write("end note""\n")


               else:
                   option2 = int(f2, base=16)
                   nbrOctetsOptions = option2 * 4 - 20
                   option_tcp = (option2 * 4 - 20) * 2
                   op_tcp = y[108:108 + option_tcp]
                   output = ''
                   count = 1
                   for k in op_tcp[::1]:
                       if count % 2 == 0:
                           output = output + k + '.'
                           count = 0
                       else:
                           output = output + k
                       count += 1
                   op_tcp = output[::1]
                   op_tcp = op_tcp.split(".")
                   elementSupprime = op_tcp.pop()
                   while nbrOctetsOptions > 0:
                       p = 0
                       while p < len(op_tcp):
                           if (op_tcp[p] == "00"):
                               dest.write("\t  TCP Option  -  End of Options List (EOL)\n")
                               dest.write("\t\tKind: End of Options List (0)\n")
                               p += 1
                               nbrOctetsOptions -= 1

                           elif (op_tcp[p] == "01"):
                               dest.write("\t  TCP Option  -  No-Operation (NOP)\n")
                               dest.write("\t\tKind: No-Operation (1)\n")
                               p += 1
                               nbrOctetsOptions -= 1

                           elif (op_tcp[p] == "02"):
                               dest.write("\t  TCP Option  -  Maximum Segment Size\n")
                               dest.write("\t\tKind: Maximum Segment Size: (2)\n")
                               length = 4
                               dest.write("\t\tLength: {}\n".format(length))
                               value = ''.join([str(x) for x in op_tcp[p + 2:p + length]])
                               dest.write("\t\tMSS Value: {}\n".format(int(value, 16)))
                               p += 4
                               nbrOctetsOptions -= 4


                           elif (op_tcp[p] == "03"):
                               dest.write("\t  TCP Option  -  Windows Scale\n")
                               dest.write("\t\tKind: Windows Scale: (3)\n")
                               length = 3
                               dest.write("\t\tLength: {}\n".format(length))
                               value1 = ''.join([str(x) for x in op_tcp[p + 2:p + length]])
                               dest.write("\t\tShift Count: {}\n".format(int(value1, 16)))
                               p += 3
                               nbrOctetsOptions -= 3

                           elif (op_tcp[p] == "04"):
                               dest.write("\t  TCP Option  -  Sack Permitted\n")
                               dest.write("\t\tKind: Sack Permitted: (4)\n")
                               length = 2
                               dest.write("\t\tLength: {}\n".format(length))
                               p += 2
                               nbrOctetsOptions -= 2

                           elif (op_tcp[p] == "08"):

                               dest.write("\t  TCP Option  -  Timestamps\n")
                               dest.write("\t\tKind: Time Stamp Option (8)\n")
                               length = 10
                               dest.write("\t\tLength: {}\n".format(length))
                               value2 = ''.join([str(x) for x in op_tcp[p + 2: p + (length // 2) + 1]])
                               dest.write("\t\tTimestamp value: {}\n".format(int(value2, 16)))
                               echo_reply = ''.join([str(x) for x in op_tcp[p + (length // 2) + 1:p + length]])
                               dest.write("\t\tTimestamp echo reply: {}\n".format(int(echo_reply, 16)))
                               p += 10
                               nbrOctetsOptions -= 10
                   http = y[108+option_tcp:]
                   methode = y[108+option_tcp:116+option_tcp]
                   Methodes = {"47455420", "504f5354", "48454144","50555420",
                               "48545450"}
                   if methode in Methodes:
                       dest.write(
                           "__________________________________________HTTP + DATA_____________________________________________\n")
                       output2 = ''
                       count2= 1
                       for k in http[::1]:
                           if count2 % 2 == 0:
                               output2 = output2 + k + '.'
                               count2 = 0
                           else:
                               output2 = output2 + k
                           count2 += 1
                       http2 = output2[::1]
                       http2 = http2.split(".")
                       elementSupprime = http2.pop()
                       dde = "0a"
                       for i in range(len(http2)):
                           if http2[i] == "0d":
                               i += 1
                               if http2[i] == dde:
                                   ss = ""
                                   entete = http2[0:http2.index(dde) + 1]
                                   entete = "".join(entete)
                       if len(entete) % 2 == 0:
                           for i in range(0, len(entete), 2):
                               sub = entete[i] + entete[i + 1]
                               ss += convertHexToDec(sub)
                       dest.write(ss + "\n\n")
                       visualisateur.write("note left of " + l + "\n")
                       visualisateur.write(str(int(b2, base=16)) + "\n")
                       visualisateur.write("end note""\n")
                       visualisateur.write(l+"-->"+m+":"+ss+"\n")
                       visualisateur.write("note left of " + m + "\n")
                       visualisateur.write(str(int(c2, base=16)) + "\n")
                       visualisateur.write("end note""\n")

                   else:
                       dest.write("_______________________DATA_____________________________\n\n")
                       visualisateur.write("note left of " + l + "\n")
                       visualisateur.write(str(int(b2, base=16)) + "\n")
                       visualisateur.write("end note""\n")
                       if (SYN == "0") and (ACK == "1"):
                           visualisateur.write(
                           l + "-->" + m + ":""TCP->" "[ACK]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                               int(e2, base=16)) + ' '"WIN=" + str(int(g2, base=16)) + ' '"windowscale="' ' + format(
                               int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                               int(value1, 16))+ ' '"Timestampsecho="' ' + format(int(echo_reply, 16)) + "\n")
                       if (SYN == "1") and (ACK == "0"):
                           visualisateur.write(
                           l + "-->" + m + ":""TCP->" "[SYN]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                               int(e2, base=16)) + ' '"WIN=" + str(int(g2, base=16)) + ' '"windowscale="' ' + format(
                               int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                               int(value2, 16))+ ' '"Timestampsecho="' ' + format(int(echo_reply, 16)) + "\n")
                       if (SYN == "1") and (ACK == "1"):
                           visualisateur.write(
                           l + "-->" + m + ":""TCP->" "[SYN/ACK]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                               int(e2, base=16)) + ' '"WIN="' ' + str(int(g2, base=16)) + ' '"windowscale="' ' + format(
                               int(value1, 16))+ ' '"Timestampsvalue="' ' + str(
                               int(value2, 16))+ ' '"Timestampsecho="' ' + format(int(echo_reply, 16)) + "\n")
                       if (FIN == "1") and (ACK == "0"):
                           visualisateur.write(
                               l + "-->" + m + ":""TCP->" "[FIN]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                                   int(e2, base=16)) + ' '"WIN="' ' + str(
                                   int(g2, base=16)) + ' '"windowscale="' ' + format(
                                   int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                                   int(value2, 16)) + ' '"Timestampsecho="' ' + format(int(echo_reply, 16)) + "\n")
                       if (FIN== "1") and (ACK == "1"):
                           visualisateur.write(
                               l + "-->" + m + ":""TCP->" "[FIN/ACK]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                                   int(e2, base=16)) + ' '"WIN="' ' + str(
                                   int(g2, base=16)) + ' '"windowscale="' ' + format(
                                   int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                                   int(value2, 16)) + ' '"Timestampsecho="' ' + format(int(echo_reply, 16)) + "\n")
                       visualisateur.write("note left of " + m + "\n")
                       visualisateur.write(str(int(c2, base=16)) + "\n")
                       visualisateur.write("end note""\n")

        else:
            dest.write("Protocol Non pris en charge \n")
            visualisateur.write(l + "-->" + m + ":""protocole non pris en charge""\n")

    f.close()
def filtrage_tcp(fich_name):
    f = open(fich_name, "r")
    lines = f.readlines()
    for i in range(len(lines)):
        x = lines[i].replace("\n", "")
        y = "".join(x)
        d = y[46:48]
        if d == "01":
            prot = "ICMP"
        if d == "06":
            prot = "TCP"
        ij = y[48:52]
        l = str(int(y[52:54], base=16)) + "." + str(int(y[54:56], base=16)) + "." + str(
            int(y[56:58], base=16)) + "." + str(int(y[58:60], base=16))
        m = str(int(y[60:62], base=16)) + "." + str(int(y[62:64], base=16)) + "." + str(
            int(y[64:66], base=16)) + "." + str(int(y[66:68], base=16))
        if prot == "TCP":
            a2 = y[29]
            if a2 == "5":
                b2 = y[68:72]
                c2 = y[72:76]
                d2 = y[76:84]
                e2 = y[84:92]
                f2 = y[92]
                r_flags = y[93:96]
                r_flags = int(r_flags, base=16)
                aa = format(r_flags)
                zz = binary(r_flags)
                tt = str(zz)
                ACK = tt[13]
                PSH = tt[14]
                SYN = tt[16]
                FIN = tt[17]
                g2 = y[96:100]
                if f2 == "5":
                    http = y[108:]
                    visualisateur2.write("note left of " + l + "\n")
                    visualisateur2.write(str(int(b2, base=16)) + "\n")
                    visualisateur2.write("end note""\n")
                    if (SYN == "0") and (ACK == "1"):
                        visualisateur2.write(
                            l + "-->" + m + ":""TCP->" "[ACK]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                                int(e2, base=16)) + ' '"WIN=" + str(int(g2, base=16)) + "\n")
                    if (SYN == "1") and (ACK == "0"):
                        visualisateur2.write(
                            l + "-->" + m + ":""TCP->" "[SYN]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                                int(e2, base=16)) + ' '"WIN=" + str(int(g2, base=16)) +
                                "\n")
                    if (SYN == "1") and (ACK == "1"):
                        visualisateur2.write(
                            l + "-->" + m + ":""TCP->" "[SYN/ACK]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                                int(e2, base=16)) + ' '"WIN="' ' + str(int(g2, base=16)) + "\n")
                    if (FIN == "1") and (ACK == "0"):
                        visualisateur2.write(
                            l + "-->" + m + ":""TCP->" "[FIN]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                                int(e2, base=16)) + ' '"WIN="' ' + str(int(g2, base=16)) + "\n")
                    if (FIN == "1") and (ACK == "1"):
                        visualisateur2.write(
                            l + "-->" + m + ":""TCP->" "[FIN/ACK]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                                int(e2, base=16)) + ' '"WIN="' ' + str(int(g2, base=16)) + "\n")
                    visualisateur2.write("note left of " + m + "\n")
                    visualisateur2.write(str(int(c2, base=16)) + "\n")
                    visualisateur2.write("end note""\n")
                else:
                    option2 = int(f2, base=16)
                    nbrOctetsOptions = option2 * 4 - 20
                    option_tcp = (option2 * 4 - 20) * 2
                    op_tcp = y[108:108 + option_tcp]
                    output = ''
                    count = 1
                    for k in op_tcp[::1]:
                        if count % 2 == 0:
                            output = output + k + '.'
                            count = 0
                        else:
                            output = output + k
                        count += 1
                    op_tcp = output[::1]
                    op_tcp = op_tcp.split(".")
                    elementSupprime = op_tcp.pop()
                    while nbrOctetsOptions > 0:
                        p = 0
                        while p < len(op_tcp):
                            if (op_tcp[p] == "00"):
                                p += 1
                                nbrOctetsOptions -= 1

                            elif (op_tcp[p] == "01"):
                                p += 1
                                nbrOctetsOptions -= 1

                            elif (op_tcp[p] == "02"):
                                length = 4
                                value = ''.join([str(x) for x in op_tcp[p + 2:p + length]])
                                p += 4
                                nbrOctetsOptions -= 4


                            elif (op_tcp[p] == "03"):
                                length = 3
                                value1 = ''.join([str(x) for x in op_tcp[p + 2:p + length]])
                                p += 3
                                nbrOctetsOptions -= 3

                            elif (op_tcp[p] == "04"):
                                length = 2
                                p += 2
                                nbrOctetsOptions -= 2

                            elif (op_tcp[p] == "08"):
                                length = 10
                                value2 = ''.join([str(x) for x in op_tcp[p + 2: p + (length // 2) + 1]])
                                echo_reply = ''.join([str(x) for x in op_tcp[p + (length // 2) + 1:p + length]])
                                p += 10
                                nbrOctetsOptions -= 10
                    http = y[108 + option_tcp:]

                    visualisateur2.write("note left of " + l + "\n")
                    visualisateur2.write(str(int(b2, base=16)) + "\n")
                    visualisateur2.write("end note""\n")
                    if (SYN == "0") and (ACK == "1"):
                        visualisateur2.write(
                            l + "-->" + m + ":""TCP->" "[ACK]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                                int(e2, base=16)) + ' '"WIN=" + str(
                                int(g2, base=16)) + ' '"windowscale="' ' + format(
                                int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                                int(value1, 16)) + ' '"Timestampsecho="' ' + format(int(echo_reply, 16)) + "\n")
                    if (SYN == "1") and (ACK == "0"):
                        visualisateur2.write(
                            l + "-->" + m + ":""TCP->" "[SYN]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                                int(e2, base=16)) + ' '"WIN=" + str(
                                int(g2, base=16)) + ' '"windowscale="' ' + format(
                                int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                                int(value2, 16)) + ' '"Timestampsecho="' ' + format(int(echo_reply, 16)) + "\n")
                    if (SYN == "1") and (ACK == "1"):
                         visualisateur2.write(
                            l + "-->" + m + ":""TCP->" "[SYN/ACK]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                                 int(e2, base=16)) + ' '"WIN="' ' + str(
                                 int(g2, base=16)) + ' '"windowscale="' ' + format(
                                  int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                                  int(value2, 16)) + ' '"Timestampsecho="' ' + format(int(echo_reply, 16)) + "\n")
                    if (FIN == "1") and (ACK == "0"):
                         visualisateur2.write(
                            l + "-->" + m + ":""TCP->" "[FIN]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                                 int(e2, base=16)) + ' '"WIN="' ' + str(
                                 int(g2, base=16)) + ' '"windowscale="' ' + format(
                                  int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                                  int(value2, 16)) + ' '"Timestampsecho="' ' + format(int(echo_reply, 16)) + "\n")
                    if (FIN == "1") and (ACK == "1"):
                         visualisateur2.write(
                            l + "-->" + m + ":""TCP->" "[FIN/ACK]"' '"SN=" + str(int(d2, base=16)) + ' '"AN=" + str(
                                 int(e2, base=16)) + ' '"WIN="' ' + str(
                                 int(g2, base=16)) + ' '"windowscale="' ' + format(
                                  int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                                  int(value2, 16)) + ' '"Timestampsecho="' ' + format(int(echo_reply, 16)) + "\n")
                    visualisateur2.write("note left of " + m + "\n")
                    visualisateur2.write(str(int(c2, base=16)) + "\n")
                    visualisateur2.write("end note""\n")

def filtrage_http(fich_name):
    f = open(fich_name, "r")
    lines = f.readlines()
    for i in range(len(lines)):
        x = lines[i].replace("\n", "")
        y = "".join(x)
        d = y[46:48]
        if d == "01":
            prot = "ICMP"
        if d == "06":
            prot = "TCP"
        l = str(int(y[52:54], base=16)) + "." + str(int(y[54:56], base=16)) + "." + str(
            int(y[56:58], base=16)) + "." + str(int(y[58:60], base=16))
        m = str(int(y[60:62], base=16)) + "." + str(int(y[62:64], base=16)) + "." + str(
            int(y[64:66], base=16)) + "." + str(int(y[66:68], base=16))
        if prot == "TCP":
                b2 = y[68:72]
                c2 = y[72:76]
                f2 = y[92]
                if f2 == "5":
                    http = y[108:]
                    methode = y[108:116]
                    Methodes = {"47455420", "504f5354", "48454144", "50555420",
                                "48545450"}
                    if methode in Methodes:
                        output2 = ''
                        count2 = 1
                        for k in http[::1]:
                            if count2 % 2 == 0:
                                output2 = output2 + k + '.'
                                count2 = 0
                            else:
                                output2 = output2 + k
                            count2 += 1
                        http2 = output2[::1]
                        http2 = http2.split(".")
                        elementSupprime = http2.pop()
                        dde = "0a"
                        for i in range(len(http2)):
                            if http2[i] == "0d":
                                i += 1
                                if http2[i] == dde:
                                    ss = ""
                                    entete = http2[0:http2.index(dde) + 1]
                                    entete = "".join(entete)
                        if len(entete) % 2 == 0:
                            for i in range(0, len(entete), 2):
                                sub = entete[i] + entete[i + 1]
                                ss += convertHexToDec(sub)
                        visualisateur2.write("note left of " + l + "\n")
                        visualisateur2.write(str(int(b2, base=16)) + "\n")
                        visualisateur2.write("end note""\n")
                        visualisateur2.write(l + "__>" + m + ":" + ss + "\n")
                        visualisateur2.write("note left of " + m + "\n")
                        visualisateur2.write(str(int(c2, base=16)) + "\n")
                        visualisateur2.write("end note""\n")
                else:
                    option2 = int(f2, base=16)
                    option_tcp = (option2 * 4 - 20) * 2
                    http = y[108 + option_tcp:]
                    methode = y[108 + option_tcp:116 + option_tcp]
                    Methodes = {"47455420", "504f5354", "48454144", "50555420",
                                "48545450"}
                    if methode in Methodes:
                        output2 = ''
                        count2 = 1
                        for k in http[::1]:
                            if count2 % 2 == 0:
                                output2 = output2 + k + '.'
                                count2 = 0
                            else:
                                output2 = output2 + k
                            count2 += 1
                        http2 = output2[::1]
                        http2 = http2.split(".")
                        elementSupprime = http2.pop()
                        dde = "0a"
                        for i in range(len(http2)):
                            if http2[i] == "0d":
                                i += 1
                                if http2[i] == dde:
                                    ss = ""
                                    entete = http2[0:http2.index(dde) + 1]
                                    entete = "".join(entete)
                        if len(entete) % 2 == 0:
                            for i in range(0, len(entete), 2):
                                sub = entete[i] + entete[i + 1]
                                ss += convertHexToDec(sub)
                        visualisateur2.write("note left of " + l + "\n")
                        visualisateur2.write(str(int(b2, base=16)) + "\n")
                        visualisateur2.write("end note""\n")
                        visualisateur2.write(l + "-->" + m + ":" + ss + "\n")
                        visualisateur2.write("note left of " + m + "\n")
                        visualisateur2.write(str(int(c2, base=16)) + "\n")
                        visualisateur2.write("end note""\n")






class Colors:
	OKGREEN = '\033[92m'
	UNDERLINE = '\033[4m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	BOLD = '\033[1m'
	ENDC = '\033[0m'

def main():
    while True:
        fileName = input(Colors.BOLD+"Entrer le nom du fichier contenant la(les) trame(s) : "+Colors.ENDC)
        try:
            fich_name = open(fileName)
        except:
            print("Ce fichier n'existe pas !! ")
        else:
            break

    ouverture(fich_name)
    print(analyse("transition.txt"))
    visualisateur.write("@enduml")

    filtre = ""
    filtres = {"protocol", "ip"}
    while True:
        choix = input(Colors.BOLD + "Voulez vous appliquer un filtre (y/n) : " + Colors.ENDC)
        try:
            if choix == "y":
                    filtre = input(Colors.BOLD + "Choissiez votre filtre (protocol/ip)  : " + Colors.ENDC)
                    try:
                        if filtre in filtres:
                            if filtre == "protocol":
                                protocol = input(Colors.BOLD + "Choissiez votre protocol (tcp/http)  : " + Colors.ENDC)
                            elif filtre == "ip":
                                direction = input(Colors.BOLD + "source ou destination ?  : " + Colors.ENDC)
                                adresse_ip = input(Colors.BOLD + "Entrez l'adresse ip  : " + Colors.ENDC)
                    except:
                        print("Choissiez un filtre valide")

            elif choix == "n":
                break
        except:
            print("Veuillez choisir y ou n !!")
        else:
            break
    if filtre == "protocol":
        if protocol == "tcp":
            print(filtrage_tcp("transition.txt"))
        elif protocol == "http":
            print(filtrage_http("transition.txt"))
        else:
            print("Merci")
    elif filtre == "ip":
        f = open("transition.txt", "r")
        lines = f.readlines()
        lignes = lines
        for i in range(len(lines)):
            x = lines[i].replace("\n", "")
            y = "".join(x)
            a = y[29]
            d = y[46:48]
            if d == "01":
                prot = "ICMP"
            if d == "06":
                prot = "TCP"
            l = str(int(y[52:54], base=16)) + "." + str(int(y[54:56], base=16)) + "." + str(
                int(y[56:58], base=16)) + "." + str(int(y[58:60], base=16))
            m = str(int(y[60:62], base=16)) + "." + str(int(y[62:64], base=16)) + "." + str(
                int(y[64:66], base=16)) + "." + str(int(y[66:68], base=16))
            if prot == "TCP":
                a2 = y[29]
                if a2 == "5":
                    b2 = y[68:72]
                    c2 = y[72:76]
                    d2 = y[76:84]
                    e2 = y[84:92]
                    f2 = y[92]
                    r_flags = y[93:96]
                    r_flags = int(r_flags, base=16)
                    aa = format(r_flags)
                    zz = binary(r_flags)
                    tt = str(zz)
                    ACK = tt[13]
                    PSH = tt[14]
                    RST = tt[15]
                    SYN = tt[16]
                    FIN = tt[17]
                    g2 = y[96:100]
                    if f2 != "5":
                        option2 = int(f2, base=16)
                        nbrOctetsOptions = option2 * 4 - 20
                        option_tcp = (option2 * 4 - 20) * 2
                        op_tcp = y[108:108 + option_tcp]
                        output = ''
                        count = 1
                        for k in op_tcp[::1]:
                            if count % 2 == 0:
                                output = output + k + '.'
                                count = 0
                            else:
                                output = output + k
                            count += 1
                        op_tcp = output[::1]
                        op_tcp = op_tcp.split(".")
                        elementSupprime = op_tcp.pop()
                        while nbrOctetsOptions > 0:
                            p = 0
                            while p < len(op_tcp):
                                if (op_tcp[p] == "00"):
                                    p += 1
                                    nbrOctetsOptions -= 1

                                elif (op_tcp[p] == "01"):
                                    p += 1
                                    nbrOctetsOptions -= 1

                                elif (op_tcp[p] == "02"):
                                    length = 4
                                    value = ''.join([str(x) for x in op_tcp[p + 2:p + length]])
                                    p += 4
                                    nbrOctetsOptions -= 4


                                elif (op_tcp[p] == "03"):
                                    length = 3
                                    value1 = ''.join([str(x) for x in op_tcp[p + 2:p + length]])
                                    p += 3
                                    nbrOctetsOptions -= 3

                                elif (op_tcp[p] == "04"):
                                    length = 2
                                    p += 2
                                    nbrOctetsOptions -= 2

                                elif (op_tcp[p] == "08"):
                                    length = 10
                                    value2 = ''.join(
                                        [str(x) for x in op_tcp[p + 2: p + (length // 2) + 1]])
                                    echo_reply = ''.join([str(x) for x in op_tcp[p + (
                                            length // 2) + 1:p + length]])
                                    p += 10
                                    nbrOctetsOptions -= 10
                        http = y[108 + option_tcp:]
                        methode = y[108 + option_tcp:116 + option_tcp]
                        Methodes = {"47455420", "504f5354", "48454144", "50555420",
                                    "48545450"}
                        if methode in Methodes:
                            output2 = ''
                            count2 = 1
                            for k in http[::1]:
                                if count2 % 2 == 0:
                                    output2 = output2 + k + '.'
                                    count2 = 0
                                else:
                                    output2 = output2 + k
                                count2 += 1
                            http2 = output2[::1]
                            http2 = http2.split(".")
                            elementSupprime = http2.pop()
                            dde = "0a"
                            for i in range(len(http2)):
                                if http2[i] == "0d":
                                    i += 1
                                    if http2[i] == dde:
                                        ss = ""
                                        entete = http2[0:http2.index(dde) + 1]
                                        entete = "".join(entete)
                            if len(entete) % 2 == 0:
                                for i in range(0, len(entete), 2):
                                    sub = entete[i] + entete[i + 1]
                                    ss += convertHexToDec(sub)
                            dest.write(ss + "\n\n")
                            if direction == "source":
                                if l == adresse_ip:
                                    visualisateur2.write("note left of " + l + "\n")
                                    visualisateur2.write(str(int(b2, base=16)) + "\n")
                                    visualisateur2.write("end note""\n")
                                    visualisateur2.write(l + "-->" + m + ":" + ss + "\n")
                                    visualisateur2.write("note left of " + m + "\n")
                                    visualisateur2.write(str(int(c2, base=16)) + "\n")
                                    visualisateur2.write("end note""\n")
                            elif direction == "destination":
                                if m == adresse_ip:
                                    visualisateur2.write("note left of " + l + "\n")
                                    visualisateur2.write(str(int(b2, base=16)) + "\n")
                                    visualisateur2.write("end note""\n")
                                    visualisateur2.write(l + "-->" + m + ":" + ss + "\n")
                                    visualisateur2.write("note left of " + m + "\n")
                                    visualisateur2.write(str(int(c2, base=16)) + "\n")
                                    visualisateur2.write("end note""\n")
                        else:
                            if direction == "source":
                                if l == adresse_ip:
                                    visualisateur2.write("note left of " + l + "\n")
                                    visualisateur2.write(str(int(b2, base=16)) + "\n")
                                    visualisateur2.write("end note""\n")
                                    if (SYN == "0") and (ACK == "1"):
                                        visualisateur2.write(
                                            l + "-->" + m + ":""TCP->" "[ACK]"' '"SN=" + str(
                                                int(d2, base=16)) + ' '"AN=" + str(
                                                int(e2, base=16)) + ' '"WIN=" + str(
                                                int(g2, base=16)) + ' '"windowscale="' ' + format(
                                                int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                                                int(value1, 16)) + ' '"Timestampsecho="' ' + format(
                                                int(echo_reply, 16)) + "\n")
                                    if (SYN == "1") and (ACK == "0"):
                                        visualisateur2.write(
                                            l + "-->" + m + ":""TCP->" "[SYN]"' '"SN=" + str(
                                                int(d2, base=16)) + ' '"AN=" + str(
                                                int(e2, base=16)) + ' '"WIN=" + str(
                                                int(g2, base=16)) + ' '"windowscale="' ' + format(
                                                int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                                                int(value2, 16)) + ' '"Timestampsecho="' ' + format(
                                                int(echo_reply, 16)) + "\n")
                                    if (SYN == "1") and (ACK == "1"):
                                        visualisateur2.write(
                                            l + "-->" + m + ":""TCP->" "[SYN/ACK]"' '"SN=" + str(
                                                int(d2, base=16)) + ' '"AN=" + str(
                                                int(e2, base=16)) + ' '"WIN="' ' + str(
                                                int(g2, base=16)) + ' '"windowscale="' ' + format(
                                                int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                                                int(value2, 16)) + ' '"Timestampsecho="' ' + format(
                                                int(echo_reply, 16)) + "\n")
                                    if (FIN == "1") and (ACK == "0"):
                                        visualisateur2.write(
                                            l + "-->" + m + ":""TCP->" "[FIN]"' '"SN=" + str(
                                                int(d2, base=16)) + ' '"AN=" + str(
                                                int(e2, base=16)) + ' '"WIN=" + str(
                                                int(g2, base=16)) + ' '"windowscale="' ' + format(
                                                int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                                                int(value1, 16)) + ' '"Timestampsecho="' ' + format(
                                                int(echo_reply, 16)) + "\n")
                                    if (FIN == "1") and (ACK == "1"):
                                        visualisateur2.write(
                                            l + "-->" + m + ":""TCP->" "[FIN/ACK]"' '"SN=" + str(
                                                int(d2, base=16)) + ' '"AN=" + str(
                                                int(e2, base=16)) + ' '"WIN=" + str(
                                                int(g2, base=16)) + ' '"windowscale="' ' + format(
                                                int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                                                int(value1, 16)) + ' '"Timestampsecho="' ' + format(
                                                int(echo_reply, 16)) + "\n")
                                    visualisateur2.write("note left of " + m + "\n")
                                    visualisateur2.write(str(int(c2, base=16)) + "\n")
                                    visualisateur2.write("end note""\n")
                            elif direction == "destination":
                                if m == adresse_ip:
                                    visualisateur2.write("note left of " + l + "\n")
                                    visualisateur2.write(str(int(b2, base=16)) + "\n")
                                    visualisateur2.write("end note""\n")
                                    if (SYN == "0") and (ACK == "1"):
                                        visualisateur2.write(
                                            l + "-->" + m + ":""TCP->" "[ACK]"' '"SN=" + str(
                                                int(d2, base=16)) + ' '"AN=" + str(
                                                int(e2, base=16)) + ' '"WIN=" + str(
                                                int(g2, base=16)) + ' '"windowscale="' ' + format(
                                                int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                                                int(value1, 16)) + ' '"Timestampsecho="' ' + format(
                                                int(echo_reply, 16)) + "\n")
                                    if (SYN == "1") and (ACK == "0"):
                                        visualisateur2.write(
                                            l + "-->" + m + ":""TCP->" "[SYN]"' '"SN=" + str(
                                                int(d2, base=16)) + ' '"AN=" + str(
                                                int(e2, base=16)) + ' '"WIN=" + str(
                                                int(g2, base=16)) + ' '"windowscale="' ' + format(
                                                int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                                                int(value2, 16)) + ' '"Timestampsecho="' ' + format(
                                                int(echo_reply, 16)) + "\n")
                                    if (SYN == "1") and (ACK == "1"):
                                        visualisateur2.write(
                                            l + "-->" + m + ":""TCP->" "[SYN/ACK]"' '"SN=" + str(
                                                int(d2, base=16)) + ' '"AN=" + str(
                                                int(e2, base=16)) + ' '"WIN="' ' + str(
                                                int(g2, base=16)) + ' '"windowscale="' ' + format(
                                                int(value1, 16)) + ' '"Timestampsvalue="' ' + str(
                                                int(value2, 16)) + ' '"Timestampsecho="' ' + format(
                                                int(echo_reply, 16)) + "\n")
                                    visualisateur2.write("note left of " + m + "\n")
                                    visualisateur2.write(str(int(c2, base=16)) + "\n")
                                    visualisateur2.write("end note""\n")
    else:
        print("Merci")


    visualisateur2.write("@enduml")

if __name__ == "__main__":
    main()



