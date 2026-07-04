import os
import hmac
import hashlib
from config import P, G, genera_chiave_privata
from utils import separatore, passo

def esegui() -> None:
    """
    SCENARIO 3: Dimostra la difesa tramite autenticazione Challenge-Response
    basata su HMAC-SHA256 con chiave pre-condivisa (PSK).
    """
    separatore("SCENARIO 3: Difesa Challenge-Response con HMAC-SHA256")

    # --- Passo 1: Chiave pre-condivisa ---
    passo(1, "Chiave segreta pre-condivisa (PSK) — conosciuta SOLO da Alice e Bob")
    psk = b"chiave_segreta_condivisa_alice_bob_2024"
    print(f"    PSK (hex) = {psk.hex()}")
    print("    Nota: la PSK è stata scambiata su un canale sicuro fuori banda")
    print("    (es. in persona, o tramite un'infrastruttura PKI).")

    # ------------------------------------------------------------------
    # --- PARTE A: Autenticazione riuscita (Alice legittima) ---
    # ------------------------------------------------------------------
    print("\n  ── PARTE A: Tentativo di Alice Legittima ──────────────────────")

    # --- Passo 2: Bob genera il nonce (challenge) ---
    passo(2, "Bob genera un nonce casuale e lo invia ad Alice (challenge)")
    nonce = os.urandom(16)   # 128 bit di casualità crittografica
    print(f"    Nonce generato da Bob (hex) = {nonce.hex()}")
    print("    [RETE] Bob → Alice : invia il nonce (il nonce può essere pubblico)")

    # --- Passo 3: Alice calcola l'HMAC (response) ---
    passo(3, "Alice calcola HMAC-SHA256(PSK, nonce) e lo invia a Bob (response)")
    firma_alice = hmac.new(psk, nonce, hashlib.sha256).digest()
    print(f"    HMAC calcolato da Alice (hex) = {firma_alice.hex()}")
    print("    [RETE] Alice → Bob : invia la firma HMAC")

    # --- Passo 4: Bob verifica la firma ---
    passo(4, "Bob verifica la firma con hmac.compare_digest (timing-safe)")
    firma_attesa = hmac.new(psk, nonce, hashlib.sha256).digest()
    autenticazione_ok = hmac.compare_digest(firma_alice, firma_attesa)
    print(f"    Firma ricevuta  (hex) = {firma_alice.hex()}")
    print(f"    Firma attesa    (hex) = {firma_attesa.hex()}")
    print(f"    hmac.compare_digest   = {autenticazione_ok}")

    if autenticazione_ok:
        print("    ✅ AUTENTICAZIONE RIUSCITA: Alice ha dimostrato di conoscere PSK.")
        print("       Procedo con lo scambio Diffie-Hellman autenticato...\n")

        # --- Passo 5: Scambio DH post-autenticazione ---
        passo(5, "Scambio DH autenticato (ora sicuro perché l'identità è verificata)")
        alice_privata  = genera_chiave_privata()
        alice_pubblica = pow(G, alice_privata, P)
        bob_privata    = genera_chiave_privata()
        bob_pubblica   = pow(G, bob_privata, P)

        print(f"    Alice invia A = {hex(alice_pubblica)[:18]}...  (Bob sa che proviene dalla vera Alice)")
        print(f"    Bob   invia B = {hex(bob_pubblica)[:18]}...  (Alice sa che proviene dal vero Bob)")

        segreto_alice = pow(bob_pubblica,  alice_privata, P)
        segreto_bob   = pow(alice_pubblica, bob_privata,  P)
        print(f"\n    Segreto calcolato da Alice (hex): {hex(segreto_alice)[:34]}...")
        print(f"    Segreto calcolato da Bob   (hex): {hex(segreto_bob)[:34]}...")

        if segreto_alice == segreto_bob:
            print(f"\n    ✅ SESSIONE SICURA STABILITA — Segreto condiviso (hex) = {hex(segreto_alice)[:34]}...")
            print("       Alice e Bob sono certi di parlare l'uno con l'altro.")
    else:
        print("    ❌ AUTENTICAZIONE FALLITA: Connessione bloccata.")

    # ------------------------------------------------------------------
    # --- PARTE B: Tentativo di Eve (attaccante MitM) ---
    # ------------------------------------------------------------------
    print("\n\n  ── PARTE B: Tentativo di Eve (MitM) ──────────────────────────")

    # --- Passo 6: Bob ri-genera un nuovo nonce ---
    passo(6, "Bob genera un nuovo nonce e lo invia (supponendo che Eve si interponga)")
    nonce_nuovo = os.urandom(16)
    print(f"    Nuovo nonce (hex) = {nonce_nuovo.hex()}")
    print("    [RETE] Bob → [EVE INTERCETTA] → Alice")

    # --- Passo 7: Eve tenta di rispondere senza la PSK ---
    passo(7, "Eve tenta di rispondere al challenge SENZA conoscere la PSK")
    psk_falsa_di_eve = b"tentativo_di_eve_chiave_errata"  # Eve non conosce la chiave reale
    firma_eve = hmac.new(psk_falsa_di_eve, nonce_nuovo, hashlib.sha256).digest()
    print(f"    Firma prodotta da Eve (hex) = {firma_eve.hex()}")
    print("    [RETE] Eve → Bob : invia la propria firma (falsa)")

    # --- Passo 8: Bob verifica la firma di Eve ---
    passo(8, "Bob verifica la firma di Eve (confronto timing-safe)")
    firma_attesa_nuovo = hmac.new(psk, nonce_nuovo, hashlib.sha256).digest()
    verifica_eve = hmac.compare_digest(firma_eve, firma_attesa_nuovo)
    print(f"    Firma di Eve    (hex) = {firma_eve.hex()}")
    print(f"    Firma attesa    (hex) = {firma_attesa_nuovo.hex()}")
    print(f"    hmac.compare_digest   = {verifica_eve}")

    if not verifica_eve:
        print()
        print("    ✅ ATTACCO BLOCCATO: La firma di Eve non corrisponde.")
        print("       Bob termina immediatamente la sessione.")
        print("       Senza PSK, Eve non può impersonare Alice, e quindi")
        print("       non può eseguire il MitM sullo scambio DH.")
    else:
        print("    ❌ ERRORE LOGICO: Eve non avrebbe dovuto superare la verifica.")

    # --- Riepilogo finale ---
    print()
    print("  " + "─" * 60)
    print("  RIEPILOGO SCENARIO 3:")
    print("    • Challenge-Response con HMAC garantisce l'autenticazione.")
    print("    • Solo chi possiede la PSK può rispondere correttamente.")
    print("    • hmac.compare_digest previene i timing attacks.")
    print("    • Lo scambio DH avviene DOPO la verifica dell'identità,")
    print("      rendendo il MitM impossibile anche in un canale ostile.")
    print("  " + "─" * 60)
