# Diffie-Hellman: Vulnerabilità MitM e Difesa Challenge-Response
**Corso:** Sicurezza dell'Informazione M  
**Progetto:** Implementazione pratica e simulazione in Python 3  

---

## Indice
1. [Descrizione del Progetto](#1-descrizione-del-progetto)
2. [Struttura del Repository](#2-struttura-del-repository)
3. [Fondamenti: il Protocollo Diffie-Hellman](#3-fondamenti-il-protocollo-diffie-hellman)
4. [Problema: Mancanza di Autenticazione in DH Base](#4-problema-mancanza-di-autenticazione-in-dh-base)
5. [Scenario 2 — Attacco Man-in-the-Middle](#5-scenario-2--attacco-man-in-the-middle)
6. [Scenario 3 — Difesa Challenge-Response con HMAC](#6-scenario-3--difesa-challenge-response-con-hmac)
7. [Come Eseguire il Progetto](#7-come-eseguire-il-progetto)

---

## 1. Descrizione del Progetto

Questo progetto dimostra in modo pratico:

- Il funzionamento corretto del protocollo **Diffie-Hellman** per lo scambio di chiavi (Scenario 1).
- La sua **vulnerabilità intrinseca agli attacchi attivi** (Man-in-the-Middle, Scenario 2).
- Come un meccanismo di **autenticazione Challenge-Response basato su HMAC-SHA256** risolve la vulnerabilità, garantendo l'identità delle parti prima che lo scambio delle chiavi abbia luogo (Scenario 3).

Il codice è scritto interamente con la libreria standard di Python 3 (`hmac`, `hashlib`, `os`), senza dipendenze esterne.

---

## 2. Struttura del Repository

```
SIcurezza/
├── config.py             # Parametri DH (P, G) e gen. chiavi
├── utils.py              # Funzioni di utilità console
├── scenario1_standard.py # Modulo: scambio in condizioni ideali
├── scenario2_mitm.py     # Modulo: simulazione intercettazione Eve
├── monitoraggio_attacco.py # Modulo: allarme debug sui segreti DH
├── scenario3_hmac.py     # Modulo: difesa Challenge-Response + anti-replay
├── main.py               # Entry point per eseguire la simulazione
└── README.md             
```

---

## 3. Fondamenti: il Protocollo Diffie-Hellman

Il protocollo **Diffie-Hellman** (DH, 1976) permette a due parti — convenzionalmente chiamate **Alice** e **Bob** — di concordare un **segreto condiviso** attraverso un canale di comunicazione pubblico (e quindi intercettabile), senza che tale segreto venga mai trasmesso esplicitamente.

### Parametri pubblici (noti a tutti)
| Simbolo | Valore | Standard |
|---------|--------|----------|
| `G` | `2` | Generatore MODP comune a tutti i gruppi RFC 3526 |
| `P` | Primo sicuro a **2048 bit** | RFC 3526 Section 3 — MODP Group 14 |


### Protocollo (Scenario 1)

```
Alice                              Bob
──────                             ───
Sceglie a (privata)                Sceglie b (privata)
A = G^a mod P    ──── A ────>      B = G^b mod P
                 <─── B ────
s = B^a mod P                      s = A^b mod P
```

**Proprietà chiave:** grazie alla commutatività del gruppo:

```
B^a mod P = (G^b)^a mod P = G^(ab) mod P
A^b mod P = (G^a)^b mod P = G^(ab) mod P
```

Entrambi ottengono `s = G^(ab) mod P` senza che `a`, `b` o `s` siano stati trasmessi. La sicurezza si basa sulla difficoltà computazionale del **Problema del Logaritmo Discreto** (DLP): dato `A = G^a mod P`, ricavare `a` è computazionalmente intrattabile per valori di `P` sufficientemente grandi.

---

## 4. Problema: Mancanza di Autenticazione in DH Base

Il protocollo DH **garantisce riservatezza**, ma **non garantisce autenticazione**. Questo è il suo limite strutturale fondamentale:

> DH non fornisce alcun meccanismo per Alice di verificare che il valore pubblico ricevuto appartenga effettivamente a Bob (e viceversa).

Questa mancanza apre la porta a qualunque **avversario attivo** capace di intercettare e modificare i messaggi sul canale, come mostrato nel Scenario 2.

---

## 5. Scenario 2 — Attacco Man-in-the-Middle

### Modello dell'attaccante

Eve è un **avversario attivo** (Dolev-Yao model): può intercettare, bloccare, modificare e iniettare messaggi sul canale tra Alice e Bob.

### Come funziona l'attacco

Eve genera **due coppie di chiavi DH proprie**, una per ciascun lato:

```
Alice                  Eve (MitM)                  Bob
──────                 ──────────                  ────
a (privata)            e1 (privata)  e2 (privata)   b (privata)
A = G^a mod P          E_A = G^e1    E_B = G^e2     B = G^b mod P

   ── A ──>  [intercetta A, invia E_B]  ──>
             [intercetta B, invia E_A]  <── B ──
```

Risultato dei calcoli del segreto condiviso:

| Parte | Calcola | Crede di parlare con |
|-------|---------|----------------------|
| Alice | `E_B^a mod P = G^(e2·a)` | Bob |
| Eve   | `A^e2 mod P = G^(a·e2)` ✓ | Alice |
| Bob   | `E_A^b mod P = G^(e1·b)` | Alice |
| Eve   | `B^e1 mod P = G^(b·e1)` ✓ | Bob |

Eve conosce **entrambi i segreti** separati. Ogni messaggio cifrato da Alice con il segreto `S_AE` viene decifrato da Eve, letto/modificato, ri-cifrato con il segreto `S_BE` e inoltrato a Bob. **La comunicazione sembra perfettamente funzionante per entrambe le vittime**, eppure Eve legge e controlla tutto il traffico.

Per rendere la demo più evidente, in modalità debug viene anche confrontato direttamente il segreto che Alice e Bob credono di condividere: se non coincide, il programma stampa un warning esplicito del tipo `[ALLARME] I segreti non coincidono: possibile MitM`.

### Perché Eve riesce?

Perché DH base non include **nessun binding** tra chiave pubblica e identità. Un valore `A` trasmesso sul canale è anonimo: chiunque può inviare un valore arbitrario spacciandolo per la chiave pubblica di un altro.

---

## 6. Scenario 3 — Difesa Challenge-Response con HMAC

### Soluzione: autenticazione prima dello scambio

L'idea è semplice e potente: **verificare l'identità di Alice prima che lo scambio DH abbia luogo**. A tale scopo si usa una **chiave segreta pre-condivisa (Pre-Shared Key, PSK)**, che Alice e Bob hanno concordato su un canale sicuro fuori banda (out-of-band).

### Il protocollo Challenge-Response

```
Bob                                        Alice
────                                       ──────
Genera nonce = os.urandom(16)
               ────── nonce ──────>
                                           firma = HMAC-SHA256(PSK, nonce)
               <───── firma ──────
Verifica: HMAC-SHA256(PSK, nonce) == firma?
Se OK → procede con DH autenticato.
Se NO → blocca la connessione.
```

### Perché Eve fallisce nello Scenario 3

Eve può intercettare il `nonce` (è trasmesso in chiaro e può essere pubblico). Tuttavia, per calcolare una firma valida, Eve deve calcolare:

```
HMAC-SHA256(PSK, nonce)
```

**Senza conoscere `PSK`, questo è computazionalmente impossibile.** HMAC-SHA256 è una funzione pseudo-random: dato un nonce e una chiave sconosciuta, l'output è indistinguibile da un valore casuale. Eve non può né dedurre la chiave dall'output, né produrre una firma valida con una chiave diversa.

Quando Eve invia una firma calcolata con la propria chiave `PSK_Eve ≠ PSK`, Bob la confronta con `HMAC-SHA256(PSK, nonce)` e i due valori **non corrispondono** → la sessione viene immediatamente terminata, **prima che qualsiasi scambio DH avvenga**.

### Proprietà di sicurezza garantite

| Proprietà | DH Base | DH + Challenge-Response |
|-----------|---------|------------------------|
| Riservatezza | ✅ | ✅ |
| Autenticazione dell'origine | ❌ | ✅ |
| Resistenza al MitM attivo | ❌ | ✅ |
| Resistenza ai timing attacks | ❌ | ✅ (con `compare_digest`) |

### Mini-scenario extra: replay attack esplicito

Oltre al tentativo diretto di Eve, la demo mostra anche un caso di **replay**: Eve intercetta una firma HMAC valida e tenta di riusarla in una sessione successiva con lo stesso nonce. La verifica HMAC da sola risulta corretta, ma il controllo di freschezza sul nonce la blocca. Questo evidenzia che il nonce deve essere **casuale, fresco e monouso**.

---

---

## 7. Come Eseguire il Progetto

Il progetto richiede solo **Python 3.6+** e nessuna dipendenza esterna.

Puoi lanciare l'intera demo oppure un singolo scenario alla volta:

```bash
python3 main.py      # esegue Scenario 1, 2 e 3 in sequenza
python3 main.py 1    # esegue solo Scenario 1
python3 main.py 2    # esegue solo Scenario 2
python3 main.py 3    # esegue solo Scenario 3
```




