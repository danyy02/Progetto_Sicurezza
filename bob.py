"""
bob.py — Processo Bob: server TCP.

Scenario 1 / 2 (porta 9000):
    Bob esegue uno scambio DH. Nel Scenario 2 crede di parlare con Alice,
    ma il peer è in realtà Eve — Bob non vede nessuna differenza.

Scenario 3 (porta 9002):
    Bob esegue prima l'autenticazione HMAC-SHA256 Challenge-Response,
    poi lo scambio DH solo se il client conosce la PSK.

Uso:
    python3 bob.py --scenario 1   # oppure 2 o 3
"""

import argparse
import hmac
import hashlib
import os
import socket
import sys

from common import (
    P, G, PSK, HOST, BOB_PORT, HMAC_PORT,
    genera_chiave_privata, invia_msg, ricevi_msg, log, log_rete,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario 1 & 2 — DH semplice
# ═══════════════════════════════════════════════════════════════════════════════

def bob_dh(porta: int, scenario: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, porta))
        srv.listen(1)
        log("Bob", f"In ascolto su {HOST}:{porta}")

        conn, addr = srv.accept()
        with conn:
            log("Bob", f"Connessione accettata da {addr[0]}:{addr[1]}")

            b_priv = genera_chiave_privata()
            B_pub  = pow(G, b_priv, P)
            log("Bob", f"Chiave privata  b  = {hex(b_priv)[:20]}...  [SEGRETO — mai trasmessa]")
            log("Bob", f"Chiave pubblica B  = {hex(B_pub)[:20]}...")

            invia_msg(conn, {"tipo": "dh_pubkey", "valore": B_pub})
            log("Bob", f"Inviata chiave pubblica B = {hex(B_pub)[:20]}...")

            msg       = ricevi_msg(conn)
            A_ricevuta = msg["valore"]
            mittente = "Alice" if scenario == 1 else "Eve"
            log_rete("←", mittente, "Bob", f"dh_pubkey  A = {hex(A_ricevuta)[:20]}...")

            segreto = pow(A_ricevuta, b_priv, P)
            log("Bob", f"Segreto S = B^a mod P  →  {hex(segreto)[:36]}...")

            invia_msg(conn, {"tipo": "ack_segreto", "hash": hex(segreto)})
            msg_fine = ricevi_msg(conn)
            log("Bob", f"Handshake completato  ✓")


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario 3 — Challenge-Response HMAC + DH
# ═══════════════════════════════════════════════════════════════════════════════

def bob_hmac(porta: int) -> None:
    nonce_usati: set[bytes] = set()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, porta))
        srv.listen(1)
        log("Bob", f"In ascolto su {HOST}:{porta}  [modalità HMAC]")

        conn, addr = srv.accept()
        with conn:
            log("Bob", f"Connessione da {addr[0]}:{addr[1]}  — avvio challenge-response")

            # ── Challenge ────────────────────────────────────────────────────
            nonce = os.urandom(16)
            log("Bob", f"Nonce (challenge) generato  = {nonce.hex()}")
            invia_msg(conn, {"tipo": "challenge", "nonce": nonce.hex()})
            log("Bob", f"Inviata challenge nonce = {nonce.hex()[:20]}...")

            # ── Response ─────────────────────────────────────────────────────
            msg            = ricevi_msg(conn)
            firma_ricevuta = bytes.fromhex(msg["firma"])

            # ── Verifica ─────────────────────────────────────────────────────
            firma_attesa = hmac.new(PSK, nonce, hashlib.sha256).digest()
            auth_ok      = hmac.compare_digest(firma_ricevuta, firma_attesa)
            nonce_fresco = nonce not in nonce_usati

            mittente = "Alice" if auth_ok else "Eve"
            log_rete("←", mittente, "Bob", f"response   HMAC  = {firma_ricevuta.hex()[:20]}...")

            log("Bob", f"Firma ricevuta  = {firma_ricevuta.hex()}")
            log("Bob", f"Firma attesa    = {firma_attesa.hex()}")
            log("Bob", f"compare_digest  = {auth_ok}    nonce fresco = {nonce_fresco}")

            if auth_ok and nonce_fresco:
                nonce_usati.add(nonce)
                log("Bob", "✅  AUTENTICAZIONE RIUSCITA — identità verificata tramite PSK")
                invia_msg(conn, {"tipo": "auth_result", "ok": True})

                # ── DH autenticato ───────────────────────────────────────────
                b_priv = genera_chiave_privata()
                B_pub  = pow(G, b_priv, P)
                invia_msg(conn, {"tipo": "dh_pubkey", "valore": B_pub})
                log("Bob", f"Inviata chiave pubblica B = {hex(B_pub)[:20]}... [DH autenticato]")

                msg2      = ricevi_msg(conn)
                A_ricevuta = msg2["valore"]
                log_rete("←", "Alice", "Bob", f"dh_pubkey  A = {hex(A_ricevuta)[:20]}...")

                segreto = pow(A_ricevuta, b_priv, P)
                log("Bob", f"✅  SESSIONE SICURA — S = {hex(segreto)[:36]}...")
                invia_msg(conn, {"tipo": "ack_segreto", "hash": hex(segreto)})
            else:
                motivo = "firma errata" if not auth_ok else "nonce già usato (replay)"
                log("Bob", f"❌  AUTENTICAZIONE FALLITA  ({motivo})  — connessione rifiutata")
                invia_msg(conn, {"tipo": "auth_result", "ok": False, "motivo": motivo})


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bob — server DH/HMAC")
    parser.add_argument("--scenario", type=int, choices=(1, 2, 3), required=True)
    args = parser.parse_args()

    if args.scenario in (1, 2):
        bob_dh(BOB_PORT, scenario=args.scenario)
    else:
        bob_hmac(HMAC_PORT)
