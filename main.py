"""
========================================================================
  Sicurezza dell'Informazione M - Progetto Pratico
  Titolo: Vulnerabilità DH e Difesa Challenge-Response con HMAC
  Autore: [Inserire nome studente]
  Data:   [Inserire data]
========================================================================
"""

import time
from config import P, G
import scenario1_standard
import scenario2_mitm
import scenario3_hmac

if __name__ == "__main__":
    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║   Sicurezza dell'Informazione M — Progetto Pratico              ║")
    print("║   Diffie-Hellman: Vulnerabilità MitM e Difesa HMAC              ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print(f"  Parametri DH: RFC 3526 MODP Group 14 (2048-bit), G = {G}")
    print(f"  P (hex) = {hex(P)[:18]}...{hex(P)[-10:]}")

    scenario1_standard.esegui()
    time.sleep(3)
    
    scenario2_mitm.esegui()
    time.sleep(3)
    
    scenario3_hmac.esegui()

    print()
    print("=" * 68)
    print("  Fine della simulazione.")
    print("=" * 68)
    print()
