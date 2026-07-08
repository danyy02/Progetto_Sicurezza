# Diffie-Hellman: Vulnerabilità MitM e Difesa Challenge-Response
**Corso:** Sicurezza dell'Informazione M  
**Progetto:** Implementazione pratica con comunicazione TCP reale — Python 3

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

Questo progetto dimostra in modo pratico e concreto:

- Il funzionamento corretto del protocollo **Diffie-Hellman** per lo scambio di chiavi (**Scenario 1**).
- La sua **vulnerabilità intrinseca agli attacchi attivi** — Man-in-the-Middle (**Scenario 2**).
- Come un meccanismo di **autenticazione Challenge-Response basato su HMAC-SHA256** risolve la vulnerabilità, garantendo l'identità delle parti *prima* che lo scambio delle chiavi abbia luogo (**Scenario 3**).

A differenza di molte demo in cui tutti i "processi" sono funzioni nello stesso script, qui **Alice, Bob ed Eve girano come processi Python separati** che comunicano tramite **socket TCP reali su localhost**. Eve è un vero proxy che intercetta i byte sulla rete — non una simulazione logica in-memory. Questo rende l'attacco MitM tangibile e dimostrabile in modo inequivocabile.

Il codice utilizza esclusivamente la **libreria standard di Python 3** (`socket`, `hmac`, `hashlib`, `os`, `subprocess`), senza dipendenze esterne.

---

## 2. Struttura del Repository

```
SIcurezza/
├── common.py          # Parametri DH (RFC 3526), framing TCP, logging colorato
├── alice.py           # Processo Alice — client TCP
├── bob.py             # Processo Bob   — server TCP
├── eve.py             # Processo Eve   — proxy MitM (intercetta Alice → Bob)
├── run_scenario.py    # Orchestratore: lancia i processi e mostra l'output
└── README.md
```

### Topologia di rete

```
Scenario 1 (DH standard):
  Alice ──TCP:9000──▶ Bob

Scenario 2 (MitM reale):
  Alice ──TCP:9001──▶ Eve ──TCP:9000──▶ Bob
         (crede sia Bob)  (proxy trasparente)

Scenario 3 (HMAC + DH):
  Alice ──TCP:9002──▶ Bob   [challenge-response prima del DH]
```

### Protocollo di messaggistica TCP

TCP è un protocollo a flusso di byte: non ha un concetto nativo di "messaggio". Ogni pacchetto è delimitato con un **header a 4 byte** (lunghezza big-endian) seguito da un payload JSON UTF-8:

```
┌──────────────────────────────┬───────────────────────────────────────┐
│  4 byte (lunghezza, BE uint) │  payload JSON  (N byte)               │
└──────────────────────────────┴───────────────────────────────────────┘
```

---

## 3. Fondamenti: il Protocollo Diffie-Hellman

Il protocollo **Diffie-Hellman** (DH, 1976) permette a due parti — Alice e Bob — di concordare un **segreto condiviso** attraverso un canale pubblico, senza trasmettere mai il segreto stesso.

### Parametri pubblici (noti a tutti)
| Simbolo | Valore | Standard |
|---------|--------|----------|
| `G` | `2` | Generatore comune a tutti i gruppi MODP RFC 3526 |
| `P` | Primo sicuro a **2048 bit** | RFC 3526 Section 3 — MODP Group 14 |

Le chiavi private vengono generate con `os.urandom(32)` (256 bit di entropia dal CSPRNG del sistema operativo), nel range `[2, P-2]`.

### Protocollo (Scenario 1)

```
Alice                              Bob
──────                             ───
Sceglie a (privata)                Sceglie b (privata)
A = G^a mod P    ──── A ────▶      B = G^b mod P
                 ◀─── B ────
s = B^a mod P                      s = A^b mod P
```

**Proprietà chiave:** grazie alla commutatività del gruppo:

```
B^a mod P = (G^b)^a mod P = G^(ab) mod P
A^b mod P = (G^a)^b mod P = G^(ab) mod P
```

Entrambi ottengono `S = G^(ab) mod P` senza che `a`, `b` o `S` siano mai stati trasmessi. La sicurezza si basa sulla difficoltà computazionale del **Problema del Logaritmo Discreto** (DLP).

---

## 4. Problema: Mancanza di Autenticazione in DH Base

Il protocollo DH **garantisce riservatezza**, ma **non garantisce autenticazione**. Questo è il suo limite strutturale fondamentale:

> DH non fornisce alcun meccanismo per Alice di verificare che il valore pubblico ricevuto appartenga effettivamente a Bob (e viceversa).

Questa mancanza apre la porta a qualunque **avversario attivo** capace di intercettare e modificare i messaggi sul canale, come mostrato nel Scenario 2.

---

## 5. Scenario 2 — Attacco Man-in-the-Middle

### Modello dell'attaccante

Eve è un **avversario attivo** (modello Dolev-Yao): può intercettare, bloccare, modificare e iniettare messaggi sul canale tra Alice e Bob.  
In questa implementazione, Eve è un **processo reale** che si siede fisicamente tra Alice e Bob a livello TCP.

### Come funziona l'attacco

Eve genera due coppie di chiavi DH proprie, una per ciascun lato, e sostituisce le chiavi pubbliche che transitano sulla rete:

```
Alice               Eve (proxy TCP)              Bob
──────              ───────────────              ───
a (privata)         e1 (priv.)  e2 (priv.)       b (privata)
A = G^a mod P       E1=G^e1     E2=G^e2          B = G^b mod P

  ──── A ────▶  ✗ [Eve intercetta A, invia E1]  ────▶
               ✗ [Eve intercetta B, invia E2]  ◀──── B ────
```

Risultato dei segreti calcolati:

| Parte | Calcola | Crede di parlare con |
|-------|---------|----------------------|
| Alice | `E2^a mod P = G^(e2·a)` | Bob |
| Eve   | `A^e2 mod P = G^(a·e2)` ✓ | Alice |
| Bob   | `E1^b mod P = G^(e1·b)` | Alice |
| Eve   | `B^e1 mod P = G^(b·e1)` ✓ | Bob |

Eve conosce **entrambi i segreti** separati. Ogni messaggio cifrato da Alice viene decifrato da Eve, potenzialmente modificato, ri-cifrato con l'altro segreto e inoltrato a Bob. La comunicazione sembra perfettamente funzionante per entrambe le vittime.

### Perché Eve riesce?

Perché DH base non include alcun **binding** tra chiave pubblica e identità. Un valore `A` trasmesso sul canale è anonimo: chiunque può sostituirlo con un proprio valore arbitrario senza che nessuno se ne accorga.

---

## 6. Scenario 3 — Difesa Challenge-Response con HMAC

### Soluzione: autenticazione prima dello scambio

L'idea è **verificare l'identità di Alice prima che lo scambio DH abbia luogo**. A tale scopo si usa una **chiave segreta pre-condivisa (PSK)**, concordata su un canale sicuro fuori banda.

### Il protocollo Challenge-Response

```
Bob                                        Alice
────                                       ──────
nonce = os.urandom(16)
           ──────── nonce ────────▶
                                           firma = HMAC-SHA256(PSK, nonce)
           ◀─────── firma ────────
verifica: HMAC-SHA256(PSK, nonce) == firma ?
  OK  → procede con DH autenticato
  NO  → blocca immediatamente la connessione
```

### Perché Eve fallisce nello Scenario 3

Eve può intercettare il `nonce` (è trasmesso in chiaro). Tuttavia, per calcolare una firma valida deve calcolare `HMAC-SHA256(PSK, nonce)` senza conoscere `PSK` — **computazionalmente impossibile**. HMAC-SHA256 è una funzione pseudo-random: l'output è indistinguibile da un valore casuale senza la chiave.

Quando Eve invia una firma calcolata con la propria chiave (`PSK_Eve ≠ PSK`), Bob la confronta con `HMAC-SHA256(PSK, nonce)` tramite **`hmac.compare_digest`** (confronto timing-safe, resistente ai timing attack) e i due valori non corrispondono → sessione rifiutata prima che qualsiasi DH avvenga.

### Proprietà di sicurezza garantite

| Proprietà | DH Base | DH + Challenge-Response |
|-----------|---------|------------------------|
| Riservatezza | ✅ | ✅ |
| Autenticazione dell'origine | ❌ | ✅ |
| Resistenza al MitM attivo | ❌ | ✅ |
| Resistenza ai timing attack | ❌ | ✅ (con `compare_digest`) |

---

## 7. Come Eseguire il Progetto

Il progetto richiede solo **Python 3.10+** e nessuna dipendenza esterna.

```bash
cd SIcurezza/

# Scenario 1 — DH standard (canale pulito)
python3 run_scenario.py --scenario 1

# Scenario 2 — MitM reale (Alice si connette a Eve credendo sia Bob)
python3 run_scenario.py --scenario 2

# Scenario 3a — HMAC + DH (Alice legittima, sessione sicura stabilita)
python3 run_scenario.py --scenario 3

# Scenario 3b — HMAC + DH (Eve tenta con PSK sbagliata → bloccata)
python3 run_scenario.py --scenario 3 --psk-sbagliata

# Demo completa: tutti e quattro gli scenari in sequenza
python3 run_scenario.py
```


