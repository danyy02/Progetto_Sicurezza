"""
Uso:
    python3 run_scenario.py --scenario 1   # DH standard: Alice ↔ Bob
    python3 run_scenario.py --scenario 2   # MitM reale:  Alice ↔ Eve ↔ Bob
    python3 run_scenario.py --scenario 3   # HMAC+DH:     Alice ↔ Bob (difeso)
    python3 run_scenario.py --scenario 3 --psk-sbagliata  # Eve tenta l'auth
    python3 run_scenario.py                # Tutti e tre in sequenza
"""

import argparse
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE  = Path(__file__).parent

# ── Stili ANSI ────────────────────────────────────────────────────────────────
C = {
    "Alice": "\033[94m",   # Blu
    "Bob":   "\033[92m",   # Verde
    "Eve":   "\033[91m",   # Rosso
    "info":  "\033[93m",   # Giallo
    "ok":    "\033[92m",   # Verde
    "err":   "\033[91m",   # Rosso
}
R  = "\033[0m"
B  = "\033[1m"
DM = "\033[2m"

W = 70   # larghezza box


def _box(testo: str, colore: str = "") -> None:
    print(f"\n{B}{colore}{testo}{R}\n")


def _titolo(testo: str) -> None:
    print(f"\n{B}{C['info']}{testo}{R}\n")


def _info(msg: str) -> None:
    print(f"  {C['info']}{B}[  ···  ]{R} {msg}", flush=True)


def _riepilogo(titolo: str, righe: list[str]) -> None:
    print()
    print(f"  {B}{C['info']}{'─' * (W - 2)}{R}")
    print(f"  {B}  {titolo}{R}")
    for r in righe:
        print(f"       {r}")
    print(f"  {B}{C['info']}{'─' * (W - 2)}{R}")
    print()


def _leggi_output(proc: subprocess.Popen, *_) -> None:
    """Thread: relaya stdout del sottoprocesso as-is.
    log() nel sottoprocesso stampa già il prefisso colorato [Ruolo] —
    aggiungerne un altro qui produrrebbe nomi doppi.
    """
    for linea in proc.stdout:
        print(linea.rstrip("\n"), flush=True)


def _avvia(script: str, args_extra: list[str] | None = None) -> subprocess.Popen:
    """Avvia un sottoprocesso Python con stdout non bufferizzato."""
    cmd = [sys.executable, "-u", str(HERE / script)] + (args_extra or [])
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )


def _attendi(*procs_e_thread) -> None:
    for x in procs_e_thread:
        x.join() if isinstance(x, threading.Thread) else x.wait()


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario 1 — DH standard
# ═══════════════════════════════════════════════════════════════════════════════

def esegui_scenario_1() -> None:
    _titolo("SCENARIO 1 — Scambio Diffie-Hellman Standard  (canale pulito, Alice ↔ Bob diretti)")

    _info("Avvio Bob  (server, porta 9000)...")
    bob = _avvia("bob.py", ["--scenario", "1"])
    time.sleep(0.3)

    _info("Avvio Alice  (client, si connette direttamente a Bob)...")
    alice = _avvia("alice.py", ["--scenario", "1"])

    t_b = threading.Thread(target=_leggi_output, args=(bob,   "Bob",   C["Bob"]))
    t_a = threading.Thread(target=_leggi_output, args=(alice, "Alice", C["Alice"]))
    t_b.start(); t_a.start()
    _attendi(t_b, t_a, bob, alice)

    _riepilogo("Scenario 1 — risultato atteso:", [
        "✅  Alice e Bob derivano lo stesso segreto  S = G^(ab) mod P",
        "✅  Il segreto non è mai transitato sul canale",
        "✅  Un osservatore passivo non può risalire ad 'a', 'b' o 'S' (DLP)",
    ])


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario 2 — MitM reale
# ═══════════════════════════════════════════════════════════════════════════════

def esegui_scenario_2() -> None:
    _titolo("SCENARIO 2 — Attacco Man-in-the-Middle  (Alice ─TCP─▶ Eve ─TCP─▶ Bob)")

    _info("Avvio Bob   (server, porta 9000 — non sa di Eve)...")
    bob = _avvia("bob.py", ["--scenario", "2"])
    time.sleep(0.3)

    _info("Avvio Eve   (proxy MitM, porta 9001 → 9000)...")
    eve = _avvia("eve.py")
    time.sleep(0.3)

    _info("Avvio Alice (client, porta 9001 — crede sia Bob)...")
    alice = _avvia("alice.py", ["--scenario", "2"])

    t_b = threading.Thread(target=_leggi_output, args=(bob,   "Bob",   C["Bob"]))
    t_e = threading.Thread(target=_leggi_output, args=(eve,   "Eve",   C["Eve"]))
    t_a = threading.Thread(target=_leggi_output, args=(alice, "Alice", C["Alice"]))
    t_b.start(); t_e.start(); t_a.start()
    _attendi(t_b, t_e, t_a, bob, eve, alice)

    _riepilogo("Scenario 2 — risultato atteso:", [
        "⚠️   S_AE ≠ S_EB  (due segreti distinti, entrambi noti ad Eve)",
        "⚠️   Alice crede di parlare con Bob, Bob crede di parlare con Alice",
        "⚠️   Eve può decifrare, leggere, modificare e re-cifrare ogni messaggio",
        "❌   DH base non offre alcuna autenticazione dell'identità del peer",
    ])


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario 3 — HMAC + DH
# ═══════════════════════════════════════════════════════════════════════════════

def esegui_scenario_3(psk_sbagliata: bool = False) -> None:
    if psk_sbagliata:
        sotto = "Eve tenta autenticazione HMAC con PSK errata → bloccata"
    else:
        sotto = "Alice legittima — Challenge-Response riuscito → DH autenticato"

    _titolo(f"SCENARIO 3 — Difesa HMAC-SHA256 + DH  ({sotto})")

    _info("Avvio Bob   (server HMAC, porta 9002)...")
    bob = _avvia("bob.py", ["--scenario", "3"])
    time.sleep(0.3)

    args_alice = ["--scenario", "3"]
    if psk_sbagliata:
        args_alice.append("--psk-sbagliata")

    chi = "Eve (PSK sbagliata)" if psk_sbagliata else "Alice (PSK corretta)"
    _info(f"Avvio Alice ({chi})...")
    alice = _avvia("alice.py", args_alice)

    t_b = threading.Thread(target=_leggi_output, args=(bob,   "Bob",   C["Bob"]))
    t_a = threading.Thread(target=_leggi_output, args=(alice, "Alice", C["Alice"]))
    t_b.start(); t_a.start()
    _attendi(t_b, t_a, bob, alice)

    if psk_sbagliata:
        _riepilogo("Scenario 3b — risultato atteso:", [
            "✅  Bob riceve una firma HMAC errata → connessione rifiutata immediatamente",
            "✅  Eve non può impersonare Alice senza conoscere la PSK",
            "✅  Lo scambio DH non ha mai luogo → MitM impossibile",
        ])
    else:
        _riepilogo("Scenario 3a — risultato atteso:", [
            "✅  Alice dimostra di conoscere PSK → autenticazione riuscita",
            "✅  DH avviene DOPO la verifica → Eve non può inserirsi",
            "✅  Alice e Bob derivano lo stesso segreto S su un canale autenticato",
            "✅  hmac.compare_digest previene i timing attack",
        ])


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Orchestratore TCP multiprocesso — DH/MitM/HMAC"
    )
    parser.add_argument("--scenario", type=int, choices=(1, 2, 3),
                        help="Scenario da eseguire (default: tutti in sequenza).")
    parser.add_argument("--psk-sbagliata", action="store_true",
                        help="(Solo scenario 3) Simula tentativo Eve con PSK errata.")
    args = parser.parse_args()

    _box("Demo TCP Multiprocesso", C["info"])
    print(f"  {DM}Alice, Bob ed Eve girano come processi separati su socket TCP reali.{R}")
    print(f"  {DM}Porte: Bob=9000  Eve=9001  HMAC=9002  (localhost){R}")
    print()

    if args.scenario == 1:
        esegui_scenario_1()
    elif args.scenario == 2:
        esegui_scenario_2()
    elif args.scenario == 3:
        esegui_scenario_3(psk_sbagliata=args.psk_sbagliata)
    else:
        esegui_scenario_1()
        time.sleep(1)
        esegui_scenario_2()
        time.sleep(1)
        esegui_scenario_3(psk_sbagliata=False)
        time.sleep(1)
        esegui_scenario_3(psk_sbagliata=True)

    
