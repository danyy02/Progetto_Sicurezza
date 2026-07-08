"""
Uso:
    python3 alice.py --scenario 1   # oppure 2 o 3
    python3 alice.py --scenario 3 --psk-sbagliata
"""

import argparse
import hmac
import hashlib
import socket
import sys
import time

from common import (
    P, G, PSK, HOST, BOB_PORT, EVE_PORT, HMAC_PORT,
    genera_chiave_privata, invia_msg, ricevi_msg, log, log_rete,
)

CONNESSIONE_RETRY = 10
CONNESSIONE_DELAY = 0.4


def _connetti(host: str, porta: int) -> socket.socket:
    """Apre una connessione TCP, ritentando fino a CONNESSIONE_RETRY volte."""
    for tentativo in range(1, CONNESSIONE_RETRY + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, porta))
            return sock
        except ConnectionRefusedError:
            log("Alice", f"Porta {porta} non ancora aperta (tentativo {tentativo}/{CONNESSIONE_RETRY})...")
            time.sleep(CONNESSIONE_DELAY)
    raise ConnectionRefusedError(f"Impossibile connettersi a {host}:{porta}.")


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario 1 & 2 — DH
# ═══════════════════════════════════════════════════════════════════════════════

def alice_dh(porta_target: int, scenario: int) -> None:
    dest = "Bob" if scenario == 1 else "Eve (credendo sia Bob)"
    log("Alice", f"Connessione a {HOST}:{porta_target}  →  {dest}")

    with _connetti(HOST, porta_target) as sock:
        log("Alice", "Connessione TCP stabilita")

        a_priv = genera_chiave_privata()
        A_pub  = pow(G, a_priv, P)
        log("Alice", f"Chiave privata  a  = {hex(a_priv)[:20]}...  [SEGRETO — mai trasmessa]")
        log("Alice", f"Chiave pubblica A  = {hex(A_pub)[:20]}...")

        msg        = ricevi_msg(sock)
        B_ricevuta = msg["valore"]
        log_rete("←", "Bob" if scenario == 1 else "Eve", "Alice", f"dh_pubkey  B = {hex(B_ricevuta)[:20]}...")

        invia_msg(sock, {"tipo": "dh_pubkey", "valore": A_pub})
        log("Alice", f"Inviata chiave pubblica A = {hex(A_pub)[:20]}...")

        segreto = pow(B_ricevuta, a_priv, P)
        log("Alice", f"Segreto S = B^a mod P  →  {hex(segreto)[:36]}...")

        ack = ricevi_msg(sock)
        invia_msg(sock, {"tipo": "fine", "status": "ok"})
        log("Alice", "Handshake completato  ✓")

        if scenario == 2:
            log("Alice", "⚠️   Alice NON sa che il segreto è stato compromesso da Eve!")


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario 3 — HMAC + DH
# ═══════════════════════════════════════════════════════════════════════════════

def alice_hmac(porta_target: int, usa_psk_corretta: bool = True) -> None:
    log("Alice", f"Connessione a {HOST}:{porta_target}  [modalità HMAC]")

    with _connetti(HOST, porta_target) as sock:

        msg   = ricevi_msg(sock)
        nonce = bytes.fromhex(msg["nonce"])
        log_rete("←", "Bob", "Alice", f"challenge  nonce = {nonce.hex()[:20]}...")

        psk_usata = PSK if usa_psk_corretta else b"tentativo_di_eve_chiave_errata"
        firma     = hmac.new(psk_usata, nonce, hashlib.sha256).digest()
        log("Alice", f"HMAC-SHA256(PSK, nonce) = {firma.hex()}")
        invia_msg(sock, {"tipo": "response", "firma": firma.hex()})
        log("Alice", f"Inviata risposta HMAC = {firma.hex()[:20]}...")

        risultato = ricevi_msg(sock)
        if not risultato["ok"]:
            log("Alice", f"❌  Autenticazione fallita: {risultato.get('motivo', '?')}")
            return

        log("Alice", "✅  Autenticazione riuscita — procedo con lo scambio DH")

        msg2       = ricevi_msg(sock)
        B_ricevuta = msg2["valore"]
        log_rete("←", "Bob", "Alice", f"dh_pubkey  B = {hex(B_ricevuta)[:20]}...  [DH autenticato]")

        a_priv = genera_chiave_privata()
        A_pub  = pow(G, a_priv, P)
        invia_msg(sock, {"tipo": "dh_pubkey", "valore": A_pub})
        log("Alice", f"Inviata chiave pubblica A = {hex(A_pub)[:20]}...")

        segreto = pow(B_ricevuta, a_priv, P)
        ack     = ricevi_msg(sock)
        log("Alice", f"✅  SESSIONE SICURA — S = {hex(segreto)[:36]}...")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Alice — client DH/HMAC")
    parser.add_argument("--scenario", type=int, choices=(1, 2, 3), required=True)
    parser.add_argument("--psk-sbagliata", action="store_true",
                        help="Usa PSK errata (simula il tentativo di Eve).")
    args = parser.parse_args()

    if args.scenario == 1:
        alice_dh(BOB_PORT, scenario=1)
    elif args.scenario == 2:
        alice_dh(EVE_PORT, scenario=2)
    else:
        alice_hmac(HMAC_PORT, usa_psk_corretta=not args.psk_sbagliata)
