"""
eve.py — Processo Eve: proxy TCP Man-in-the-Middle reale.

Topologia di rete:

    Alice ──[TCP]──▶ EVE_PORT:9001 ──[TCP]──▶ BOB_PORT:9000 ──▶ Bob

Eve si comporta come un nodo di rete "malevolo" tra Alice e Bob:
  • Ascolta su EVE_PORT (9001): Alice si connette qui credendo sia Bob.
  • Si connette a Bob su BOB_PORT (9000): Bob crede che sia Alice.
  • Sostituisce le chiavi pubbliche DH con le proprie.
  • Stabilisce due sessioni DH separate: Alice↔Eve e Eve↔Bob.
  • Conosce ENTRAMBI i segreti → può leggere/modificare ogni messaggio.
  • Alice e Bob non rilevano nulla di anomalo.

Uso:
    python3 eve.py
"""

import socket
import sys

from common import (
    P, G, HOST, BOB_PORT, EVE_PORT,
    genera_chiave_privata, invia_msg, ricevi_msg,
    log, log_rete,
)



def eve_mitm() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, EVE_PORT))
        srv.listen(1)
        log("Eve", f"Proxy MitM attivo  {HOST}:{EVE_PORT}  ──▶  {HOST}:{BOB_PORT}")
        log("Eve", f"In attesa di Alice (che crede sia Bob)...")

        conn_alice, addr_alice = srv.accept()
        log("Eve", f"Alice connessa da {addr_alice[0]}:{addr_alice[1]}  ← vittima acquisita")

    # ── Connessione verso Bob ─────────────────────────────────────────────────
    log("Eve", f"Apertura connessione verso Bob su {HOST}:{BOB_PORT}")
    conn_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn_bob.connect((HOST, BOB_PORT))
    log("Eve", "Connessione verso Bob stabilita  — Eve è in mezzo!")

    with conn_alice, conn_bob:

        # ── Generazione chiavi Eve ────────────────────────────────────────────
        e1_priv = genera_chiave_privata()   # e1: chiave privata lato Bob
        E1_pub  = pow(G, e1_priv, P)        # E1 = G^e1 mod P  (inviata a Bob)
        e2_priv = genera_chiave_privata()   # e2: chiave privata lato Alice
        E2_pub  = pow(G, e2_priv, P)        # E2 = G^e2 mod P  (inviata ad Alice)

        print(flush=True)
        log("Eve", "━━━ CHIAVI GENERATE DA EVE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        log("Eve", f"Chiave privata Eve→Bob   (e1) = {hex(e1_priv)[:20]}...")
        log("Eve", f"Chiave pubblica Eve→Bob  (E1) = {hex(E1_pub)[:20]}...  [sostituirà A di Alice]")
        log("Eve", f"Chiave privata Eve→Alice (e2) = {hex(e2_priv)[:20]}...")
        log("Eve", f"Chiave pubblica Eve→Alice(E2) = {hex(E2_pub)[:20]}...  [sostituirà B di Bob]")
        log("Eve", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        # ── Lato Bob: Eve si spaccia per Alice ────────────────────────────────
        #
        # Bob invia B → Eve riceve, NON la gira ad Alice, invia E1 al suo posto.
        #
        msg_bob = ricevi_msg(conn_bob)
        B_reale = msg_bob["valore"]
        log_rete("←", "Bob",  "Eve",   f"dh_pubkey  B  = {hex(B_reale)[:20]}...  ★ INTERCETTATA")

        invia_msg(conn_bob, {"tipo": "dh_pubkey", "valore": E1_pub})
        log("Eve", f"Sostituita chiave pubblica A con E1 = {hex(E1_pub)[:20]}... inviata a Bob")

        segreto_eve_bob = pow(B_reale, e1_priv, P)
        log("Eve", f"S_EB = B^e1 mod P  =  {hex(segreto_eve_bob)[:36]}...  ← Eve conosce questo segreto")

        ack_bob = ricevi_msg(conn_bob)   # ACK di Bob: pensa di aver finito con Alice

        # ── Lato Alice: Eve si spaccia per Bob ────────────────────────────────
        #
        # Eve invia E2 ad Alice al posto di B.
        #
        invia_msg(conn_alice, {"tipo": "dh_pubkey", "valore": E2_pub})
        log("Eve", f"Sostituita chiave pubblica B con E2 = {hex(E2_pub)[:20]}... inviata ad Alice")

        msg_alice = ricevi_msg(conn_alice)
        A_reale   = msg_alice["valore"]
        log_rete("←", "Alice","Eve",   f"dh_pubkey  A  = {hex(A_reale)[:20]}...  ★ INTERCETTATA")

        segreto_eve_alice = pow(A_reale, e2_priv, P)
        log("Eve", f"S_AE = A^e2 mod P  =  {hex(segreto_eve_alice)[:36]}...  ← Eve conosce questo segreto")

        # Completamento handshake verso Alice e Bob
        invia_msg(conn_alice, {"tipo": "ack_segreto", "hash": hex(segreto_eve_alice)})
        _ = ricevi_msg(conn_alice)
        invia_msg(conn_bob, {"tipo": "fine", "status": "ok"})

        # ── Segreti catturati (Eve li mostra, poi termina) ────────────────────
        print(flush=True)
        log("Eve", f"━━━ Segreti catturati ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        log("Eve", f"S_AE (Alice↔Eve) = {hex(segreto_eve_alice)[:50]}...")
        log("Eve", f"S_EB (Eve↔Bob)   = {hex(segreto_eve_bob)[:50]}...")
        log("Eve", f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")


if __name__ == "__main__":
    eve_mitm()
