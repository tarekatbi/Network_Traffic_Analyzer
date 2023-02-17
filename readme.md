#              Visualisateur de trafic 

Ce projet est un visualisateur de trafic. Il a étè codé en python.Il permet de visualiser le trafic.

## Contenu de l'archive 
L'archive contient:
1. Le fichier main.py , le code source du projet .
2. Le fichier howto qui éxplique comment lancer le programme.
3. Deux fichiers .txt: Dest.txt qui contient les informations jugées pertinentes pour chacune des trames, et un fichier qui contient les différentes trames qu'on veut analyser et visualiser. 
4. Un fichier visualisateur.puml qui contient le résultat de la viualisation.

Une fois le programme est lancée :

On donne la main à l'utilisateur de donner le fichier texte qui contient les trames qu'il veut visualiser ; à condition que le fichier sera dans le repertoire qui contient le main.py.
Ensuite on donne le choix à l'utilisateur d'appliquer des filtres ou non ; si c'est oui choisir entre tcp ,http ,adresse ip et adresse mac.
le programme principal fait appel à deux fonctions importantes : ouverture() et analyse().


**La première fonction qui est ouverture() fait les taches suivantes:**
1. ouvre le fichier original c'est à dire le fichier qui contient les trames telles qu'elles sont capturées sur wireshark en mode lécture.
2. ensuite elle fait appel à la fonction enlever_espace qui prend la liste qui a étè generée par la fonction précédente et enleve les espaces qui séparent les différents caractères de chaque élèment de la liste.
3. par la suite il enleve les offset avec la fonction skip_offset qui supprime les 4 premiers caractères de chaque élèment  de la liste .
4. on ouvre un fichier transition.txt en écriture où chaque ligne de ce fichier est une trame de notre fichier original.


**La deuxieme fonction qui est analyse()** :
5. qui prend le fichier trans.txt qui a étè generé par la fonction ouverture() ;et le parcourt ligne par ligne; et pour chaque ligne elle fait le travail qui suit:
1. elle parcourt la ligne jusqu'à sa taille maximum et repère chaque champs selon les annexes sachant que nos trames sont des trames ethernet qui encapsulent le protocole ip .
2. on récupere les adresses mac destinations et sources en comptant 12 positions qui montrent exactement les 6 octets reservés pour la mac destination et la mac source .Qui seront inscrites dans le fichier dest.txt qui est a étè ouvert  en mode écriture .
3. récupere également les adresses IP sources et destinations le protocole encapsulé et les inserent dans le fichier dest.txt pour chaque trame lue.
4. elle explore vraiment le protocole TCP vu qu'elle prend en considération les différentes options et essentiellement elle affiche que deux  sur le visualisateur :TIME STAMPS et WINDOWSCALE .
5. présence du protocole HTTP est aussi detéctée par cette fonction ; la méthode et  la version sont  affichés sur notre visualisateur. 


**La façon dont on affiche notre visualisateur est comme suit :**
1. on s'est inspiré du diagramme de séquence UML qui est éxactement semblable à notre visualisateur .
    et le langage python nous offre une opportunité d'afficher un diagramme de séquence d'une manière dynamique c'est à dire les acteurs ainsi que les interractions entre acteurs sont  liés à nos trames ; tel que nos acteurs sont les deux parties communiquantes repèrées avec leurs adresses IP . Les interractions sont les informations récupérées lors de l'analyse le protocol encapsulé ,SYN ,ACK, WIN ,LES OPTIONS ,LA MÉTODE HTTP LA VERSION. 
et cela a étè réalisé de la manière suivante :
2. la bibliothèque PLANTUML est néessaire ainsi que GRAPHVIZ ;
 on ouvre un ficher nommé visualisateur.puml en écriture ; où on écrit à chaque itération dans notre programme les deux acteurs repèrés par adresse ip et les les différentes informations pertinentes sous forme d'interractions entre les deux acteurs tout en réspectant la syntaxe d'écriture dans un fichier d'extension puml que nous allons vous montrer dans le code suivant :
     192.10.3.4 "-->"192.8.9.0":" [SYN/ACK] : la machine dont l'IP est 192.10.3.4 est la machine d'où provient la communication et la machine dont l'IP est 192.8.9.0 est la machine qui reçoit ce qui vient aprés les deux points sont les informations pertinantes .
Donc la visualisations est au niveau de notre fichier avec l'extension .puml qui devra etre dans un environnement de developpement python afin de visualiser les différentes interractions .

 
