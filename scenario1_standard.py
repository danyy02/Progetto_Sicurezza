from config import P, G, genera_chiave_privata
from utils import separatore, passo

def esegui() -> None:
    """
    SCENARIO 1: Dimostra il protocollo Diffie-Hellman in condizioni ideali.
    Alice e Bob calcolano con successo lo stesso segreto condiviso.
    """
    separatore("SCENARIO 1: Scambio Diffie-Hellman Standard (Canale Pulito)")

    # --- Passo 1: Parametri pubblici ---
    passo(1, "Parametri pubblici condivisi (noti a tutti) — RFC 3526 Group 14")
    print(f"    G (generatore) = {G}")
    print(f"    P (primo 2048-bit, hex) = {hex(P)[:18]}...{hex(P)[-10:]}")
    print(f"    (Primo sicuro a 2048 bit — RFC 3526 Section 3)")

    # --- Passo 2: Alice genera chiave privata e pubblica ---
    passo(2, "Alice genera la propria coppia di chiavi (256 bit di entropia)")
    alice_privata  = genera_chiave_privata()
    alice_pubblica = pow(G, alice_privata, P)
    print(f"    Chiave PRIVATA di Alice (a, hex) = {hex(alice_privata)[:18]}...  [SEGRETO]")
    print(f"    Chiave PUBBLICA di Alice (A = G^a mod P, hex) = {hex(alice_pubblica)[:18]}...")
    print(f"    [Inviata a Bob sul canale pubblico]")

    # --- Passo 3: Bob genera chiave privata e pubblica ---
    passo(3, "Bob genera la propria coppia di chiavi (256 bit di entropia)")
    bob_privata  = genera_chiave_privata()
    bob_pubblica = pow(G, bob_privata, P)
    print(f"    Chiave PRIVATA di Bob   (b, hex) = {hex(bob_privata)[:18]}...  [SEGRETO]")
    print(f"    Chiave PUBBLICA di Bob  (B = G^b mod P, hex) = {hex(bob_pubblica)[:18]}...")
    print(f"    [Inviata ad Alice sul canale pubblico]")

    # --- Passo 4: Scambio delle chiavi pubbliche ---
    passo(4, "Scambio delle chiavi pubbliche sul canale (in chiaro, ~2048 bit)")
    print(f"    Alice → Bob  : trasmette A (2048-bit) = {hex(alice_pubblica)[:18]}...")
    print(f"    Bob   → Alice: trasmette B (2048-bit) = {hex(bob_pubblica)[:18]}...")

    # --- Passo 5: Calcolo del segreto condiviso ---
    passo(5, "Calcolo indipendente del segreto condiviso (operazione mod P)")
    segreto_alice = pow(bob_pubblica,  alice_privata, P)
    segreto_bob   = pow(alice_pubblica, bob_privata,  P)
    print(f"    Alice calcola: S = B^a mod P  →  {hex(segreto_alice)[:18]}...")
    print(f"    Bob   calcola: S = A^b mod P  →  {hex(segreto_bob)[:18]}...")
    print(f"    Entrambi ottengono: S = G^(ab) mod P")

    # --- Passo 6: Verifica ---
    passo(6, "Verifica della corrispondenza dei segreti")
    if segreto_alice == segreto_bob:
        print(f"    ✅ SUCCESSO: Segreto condiviso (hex) = {hex(segreto_alice)[:34]}...")
        print(f"       Alice e Bob hanno derivato lo stesso S = G^(ab) mod P")
        print(f"       senza che il segreto abbia mai transitato sul canale.")
    else:
        print("    ❌ ERRORE: I segreti non coincidono (non dovrebbe mai accadere).")
