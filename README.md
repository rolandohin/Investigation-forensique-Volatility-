# Analyse mémoire avec Volatility — Investigation forensique

> Write-up d'un lab d'analyse mémoire (Security Blue Team).
> Objectif : à partir de captures mémoire (RAM) de machines Windows
> compromises, retrouver la trace de l'activité malveillante.

## Contexte

L'analyse mémoire (*memory forensics*) consiste à examiner une capture de la
mémoire vive d'un système pour y retrouver des traces d'activité qui
n'apparaissent pas sur le disque : processus en cours, connexions réseau,
commandes exécutées, code injecté. C'est une source de preuves essentielle en
réponse à incident, car de nombreux malwares ne résident qu'en mémoire.

L'outil utilisé est **Volatility**, le framework de référence pour ce type
d'analyse. Le lab s'appuie sur deux captures, `memdump1.mem` et `memdump2.mem`.

Préalable utile : passer le terminal en Bash (`bash`) pour bénéficier de
l'autocomplétion et de l'historique des commandes. Volatility se trouve dans
`/volatility/`, les captures dans `/home/ubuntu/Desktop/Volatility Exercise/`.

---

## Étape 1 — Identifier le profil de l'image

Avant toute analyse, Volatility doit connaître le type de système dont provient
la capture (version de Windows, architecture). C'est une étape obligatoire :
sans le bon profil, les plugins ne savent pas interpréter les structures
mémoire.

```bash
python vol.py -f "/home/ubuntu/Desktop/Volatility Exercise/memdump1.mem" imageinfo
```
![texte alternatif](chemin/vers/image.png)

> Astuce : si le chemin contient des espaces, l'entourer de guillemets (ou
> échapper les espaces avec `\`), sinon Volatility ne lit pas le fichier.

La sortie propose un ou plusieurs profils suggérés — on retient le premier
proposé. Elle indique aussi le nombre de processeurs de la machine d'origine et
l'adresse de la structure **KDBG** (`_KDDEBUGGER_DATA64`), utilisée ensuite par
des plugins comme `pslist` ou `modules` pour localiser les structures noyau.

Les informations clés extraites ici : profil suggéré, nombre de processeurs,
adresse KDBG.

---

## Étape 2 — Lister les processus

Deux plugins fondamentaux pour observer les processus actifs au moment de la
capture :

- **`pslist`** — liste les processus de façon linéaire.
- **`pstree`** — affiche les relations parent-enfant, ce qui est bien plus
  parlant pour repérer une anomalie.

Pour compter les occurrences d'un processus précis, on combine `pslist` avec
`grep` et éventuellement `wc -l` :

```bash
python vol.py -f "...memdump1.mem" --profile=Win7SP1x64 pslist | grep "svchost.exe" | wc -l
```

C'est une démarche typique : `svchost.exe` est un processus système Windows
parfaitement légitime et présent en plusieurs exemplaires — mais c'est aussi un
nom fréquemment usurpé par des malwares pour se fondre dans la masse.

---

## Étape 3 — Repérer le processus malveillant

C'est ici que `pstree` prend tout son sens. En observant les relations
parent-enfant, une anomalie saute aux yeux : l'un des `svchost.exe` engendre un
processus enfant `cmd.exe`, lui-même utilisant `ping.exe`.

Ce comportement est anormal. Un `svchost.exe` légitime n'a aucune raison de
lancer un interpréteur de commandes qui exécute des `ping`. C'est un signe
caractéristique d'un processus usurpant un nom système pour masquer une activité
malveillante (technique de *masquerading*, T1036 dans MITRE ATT&CK).

Le PID de ce `svchost.exe` suspect est ainsi identifié.

---

## Étape 4 — Examiner la ligne de commande d'un processus

Pour comprendre ce qu'un processus faisait réellement, le plugin **`cmdline`**
extrait les arguments de ligne de commande avec lesquels il a été lancé :

```bash
python vol.py -f "...memdump1.mem" --profile=Win7SP1x64 cmdline -p 2352
```

La ligne de commande révèle souvent l'intention : chemin d'un exécutable
suspect, paramètres de connexion, script appelé.

---

## Étape 5 — Analyser les connexions réseau (memdump2)

Sur la seconde capture, suspectée d'infection persistante, on cherche l'IP
malveillante associée au malware. Le plugin **`netscan`** liste les connexions
réseau présentes en mémoire :

```bash
python vol.py -f "...memdump2.mem" --profile=Win7SP1x64 netscan
```

L'analyse consiste à repérer les **adresses distantes inhabituelles** (IP
publiques) contactées par des processus qui n'ont aucune raison de communiquer
vers Internet. Le cas observé est exemplaire : le processus **WINWORD.EXE**
(Microsoft Word) communique vers une IP externe sur le port 80 (HTTP).

Word qui établit une connexion HTTP sortante vers une IP publique inconnue, c'est
le scénario classique du **document piégé** : une macro malveillante dans un
fichier Word télécharge une charge depuis un serveur distant. Cela correspond
aux techniques d'accès initial par pièce jointe (*phishing*) et de
téléchargement de charge (*ingress tool transfer*, T1105).

---

## Étape 6 — Extraire et hasher le processus malveillant

Dernière étape : extraire l'exécutable du processus suspect pour l'analyser. Le
plugin **`procdump`** écrit le processus sur disque à partir de son PID :

```bash
python vol.py -f "...memdump2.mem" --profile=Win7SP1x64 procdump -p 2940
```

On calcule ensuite l'empreinte du fichier extrait :

```bash
md5sum executable.<pid>.exe
```

Ce hash MD5 permet de **caractériser l'échantillon** : on peut le soumettre à un
service de threat intelligence (VirusTotal par exemple) pour confirmer la nature
malveillante et identifier la famille de malware. C'est le pont entre
l'investigation forensique et la threat intelligence.

---

## Ce que ce lab illustre

L'analyse mémoire donne accès à des informations que le disque ne révèle pas :
processus volatils, connexions réseau actives, code chargé en RAM. La méthode
suivie ici reflète une investigation réelle :

1. **Identifier** le système (profil).
2. **Cartographier** les processus et repérer les anomalies (relations
   parent-enfant aberrantes, noms usurpés).
3. **Investiguer** les processus suspects (ligne de commande, connexions).
4. **Extraire et caractériser** l'échantillon malveillant (dump, hash, threat
   intelligence).

Chaque observation peut être reliée au référentiel **MITRE ATT&CK**, ce qui
structure l'analyse et facilite la communication des conclusions — la démarche
attendue d'un analyste SOC ou DFIR face à un incident.

## Plugins Volatility utilisés

| Plugin | Rôle |
|--------|------|
| `imageinfo` | Identifier le profil de la capture mémoire |
| `pslist`    | Lister les processus actifs |
| `pstree`    | Afficher les relations parent-enfant |
| `cmdline`   | Extraire la ligne de commande d'un processus |
| `netscan`   | Lister les connexions réseau |
| `procdump`  | Extraire un processus pour analyse |

---

*Write-up réalisé dans le cadre de ma préparation à la certification BTL1
(Security Blue Team). À visée pédagogique.*
