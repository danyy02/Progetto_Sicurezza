import argparse
import time
from config import P, G
import scenario1_standard
import scenario2_mitm
import scenario3_hmac

def esegui_scenario(numero: int) -> None:
    if numero == 1:
        scenario1_standard.esegui()
    elif numero == 2:
        scenario2_mitm.esegui()
    elif numero == 3:
        scenario3_hmac.esegui()
    else:
        raise ValueError(f"Scenario non valido: {numero}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Esegue la demo completa o un singolo scenario Diffie-Hellman/HMAC."
    )
    parser.add_argument(
        "scenario",
        nargs="?",
        type=int,
        choices=(1, 2, 3),
        help="Numero dello scenario da eseguire (1, 2 o 3). Se omesso, esegue tutti gli scenari.",
    )
    args = parser.parse_args()

    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║   Sicurezza dell'Informazione M — Progetto Pratico              ║")
    print("║   Diffie-Hellman: Vulnerabilità MitM e Difesa HMAC              ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print(f"  Parametri DH: RFC 3526 MODP Group 14 (2048-bit), G = {G}")
    print(f"  P (hex) = {hex(P)[:18]}...{hex(P)[-10:]}")

    if args.scenario is None:
        scenario1_standard.esegui()
        time.sleep(3)

        scenario2_mitm.esegui()
        time.sleep(3)

        scenario3_hmac.esegui()
    else:
        esegui_scenario(args.scenario)

    print()
    print("=" * 68)
    print("  Fine della simulazione.")
    print("=" * 68)
    print()
