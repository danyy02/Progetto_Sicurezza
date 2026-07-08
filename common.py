"""
common.py — Parametri DH condivisi e protocollo di messaggistica TCP.

Ogni messaggio sulla rete è strutturato come:
    [4 byte big-endian: lunghezza payload] [payload JSON UTF-8]

Questo garantisce il framing corretto su stream TCP (che non ha
concetto di "messaggio" — solo flusso di byte).
"""

import json
import os
import socket
import struct

# ── Parametri DH: RFC 3526 MODP Group 14 (2048 bit) ──────────────────────────
P = int(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
    "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
    "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
    "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
    "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF".replace(" ", ""),
    16,
)
G = 2  # Generatore standard MODP RFC 3526

# ── Indirizzi di rete ─────────────────────────────────────────────────────────
HOST       = "127.0.0.1"
BOB_PORT   = 9000   # Bob ascolta qui (scenari 1 e 2)
EVE_PORT   = 9001   # Eve ascolta qui e fa da proxy verso Bob (scenario 2)
HMAC_PORT  = 9002   # Bob ascolta qui per lo scenario HMAC (scenario 3)

# ── Chiave pre-condivisa per scenario 3 (HMAC) ───────────────────────────────
PSK = b"chiave_segreta_condivisa_alice_bob_2026"


def genera_chiave_privata() -> int:
    """Genera una chiave privata DH a 256 bit crittograficamente sicura."""
    return int.from_bytes(os.urandom(32), "big") % (P - 2) + 2


# ── Framing TCP: lunghezza (4 byte) + payload JSON ───────────────────────────

def invia_msg(sock: socket.socket, dati: dict) -> None:
    """
    Serializza `dati` in JSON e lo invia sul socket con un header a 4 byte
    che indica la lunghezza del payload. Consente al ricevente di leggere
    esattamente i byte giusti anche se il kernel li frammenta su più segmenti.
    """
    payload = json.dumps(dati).encode("utf-8")
    header  = struct.pack(">I", len(payload))
    sock.sendall(header + payload)


def ricevi_msg(sock: socket.socket) -> dict:
    """
    Legge un messaggio completo dal socket usando il framing a 4 byte.
    Restituisce il dizionario Python deserializzato dal JSON.
    Solleva ConnectionError se la connessione viene chiusa inaspettatamente.
    """
    raw_len = _leggi_esatto(sock, 4)
    lung    = struct.unpack(">I", raw_len)[0]
    payload = _leggi_esatto(sock, lung)
    return json.loads(payload.decode("utf-8"))


def _leggi_esatto(sock: socket.socket, n: int) -> bytes:
    """Legge esattamente `n` byte dal socket, gestendo i segmenti TCP parziali."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connessione chiusa inaspettatamente.")
        buf += chunk
    return buf


# ── Colori ANSI ───────────────────────────────────────────────────────────────
COLORI = {
    "Alice": "\033[94m",    # Blu
    "Bob":   "\033[92m",    # Verde
    "Eve":   "\033[91m",    # Rosso
    "NET":   "\033[95m",    # Magenta (traffico di rete)
    "OK":    "\033[92m",    # Verde
    "WARN":  "\033[93m",    # Giallo
    "ERR":   "\033[91m",    # Rosso
}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"


def log(ruolo: str, messaggio: str) -> None:
    """Stampa un messaggio di log con prefisso colorato e allineato."""
    colore = COLORI.get(ruolo, "")
    tag    = f"{BOLD}{colore}[{ruolo:5s}]{RESET}"
    print(f"  {tag} {messaggio}", flush=True)


def log_rete(direzione: str, mittente: str, destinatario: str, contenuto: str) -> None:
    """
    Stampa una riga che rappresenta visivamente un pacchetto TCP in transito.
    Esempio:  ──▶  Alice → Bob   A = 0x1a2b...
    """
    freccia = f"{COLORI['NET']}{BOLD}──▶{RESET}"
    parti   = f"{BOLD}{mittente}{RESET} → {BOLD}{destinatario}{RESET}"
    print(f"  {freccia}  {parti}   {DIM}{contenuto}{RESET}", flush=True)
