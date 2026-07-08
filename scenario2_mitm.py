from config import P, G, genera_chiave_privata
from monitoraggio_attacco import confronta_segreti
from utils import separatore, passo

def esegui() -> None:
    """
    SCENARIO 2: Dimostra come un avversario attivo (Eve) può inserirsi
    nel mezzo dello scambio DH, ingannando sia Alice che Bob.
    """
    separatore("SCENARIO 2: Attacco Man-in-the-Middle (Eve si interpone)")

    # --- Passo 1: Generazione chiavi ---
    passo(1, "Alice e Bob generano le proprie coppie di chiavi (RFC 3526, 256-bit privata)")
    alice_privata  = genera_chiave_privata()
    alice_pubblica = pow(G, alice_privata, P)
    bob_privata    = genera_chiave_privata()
    bob_pubblica   = pow(G, bob_privata, P)
    print(f"    Alice: a (hex) = {hex(alice_privata)[:18]}...,  A (hex) = {hex(alice_pubblica)[:18]}...")
    print(f"    Bob:   b (hex) = {hex(bob_privata)[:18]}...,  B (hex) = {hex(bob_pubblica)[:18]}...")

    # --- Passo 2: Eve genera le proprie chiavi ---
    passo(2, "Eve genera le proprie coppie di chiavi (una per ciascun lato)")
    eve_privata_verso_alice  = genera_chiave_privata()               # e1: chiave privata Eve lato Alice
    eve_pubblica_verso_alice = pow(G, eve_privata_verso_alice, P)    # E_A = G^e1 mod P
    eve_privata_verso_bob    = genera_chiave_privata()               # e2: chiave privata Eve lato Bob
    eve_pubblica_verso_bob   = pow(G, eve_privata_verso_bob, P)      # E_B = G^e2 mod P
    print(f"    Eve (verso Alice): e1 = {hex(eve_privata_verso_alice)[:18]}...,  E_A = {hex(eve_pubblica_verso_alice)[:18]}...")
    print(f"    Eve (verso Bob):   e2 = {hex(eve_privata_verso_bob)[:18]}...,  E_B = {hex(eve_pubblica_verso_bob)[:18]}...")

    # --- Passo 3: Intercettazione e sostituzione ---
    passo(3, "Eve intercetta A e B e li sostituisce con le proprie chiavi pubbliche")
    print(f"    [RETE] Alice invia A = {hex(alice_pubblica)[:18]}...")
    print(f"           → [EVE INTERCETTA e SOSTITUISCE con E_A] →")
    print(f"           Bob riceve E_A = {hex(eve_pubblica_verso_alice)[:18]}...")
    print()
    print(f"    [RETE] Bob   invia B = {hex(bob_pubblica)[:18]}...")
    print(f"           → [EVE INTERCETTA e SOSTITUISCE con E_B] →")
    print(f"           Alice riceve E_B = {hex(eve_pubblica_verso_bob)[:18]}...")

    # --- Passo 4: Calcolo dei segreti ---
    passo(4, "Calcolo dei segreti separati (Alice↔Eve e Bob↔Eve)")

    # Alice crede di calcolare il segreto con Bob, ma usa E_B (chiave pubblica di Eve)
    segreto_alice          = pow(eve_pubblica_verso_bob,   alice_privata,        P)
    # Eve calcola lo stesso segreto dal lato Alice
    segreto_eve_lato_alice = pow(alice_pubblica,           eve_privata_verso_bob, P)

    # Bob crede di calcolare il segreto con Alice, ma usa E_A (chiave pubblica di Eve)
    segreto_bob            = pow(eve_pubblica_verso_alice, bob_privata,           P)
    # Eve calcola lo stesso segreto dal lato Bob
    segreto_eve_lato_bob   = pow(bob_pubblica,             eve_privata_verso_alice, P)

    alice_uguale_eve = (segreto_alice == segreto_eve_lato_alice)
    bob_uguale_eve   = (segreto_bob   == segreto_eve_lato_bob)

    print(f"    Alice crede che S = {hex(segreto_alice)[:18]}... (G^(ab) mod P)")
    print(f"    Eve   sa che S_AE = {hex(segreto_eve_lato_alice)[:18]}... ← UGUALE ad Alice: {alice_uguale_eve}")
    print()
    print(f"    Bob   crede che S = {hex(segreto_bob)[:18]}... (G^(ab) mod P)")
    print(f"    Eve   sa che S_BE = {hex(segreto_eve_lato_bob)[:18]}... ← UGUALE a Bob:   {bob_uguale_eve}")

    print()
    confronta_segreti(segreto_alice, segreto_bob)

    # --- Passo 5: Conclusione ---
    passo(5, "Analisi dell'attacco")
    print(f"    Segreto Alice-Eve (S_AE): {hex(segreto_alice)[:34]}...  ← Eve lo conosce ✅")
    print(f"    Segreto Bob-Eve   (S_BE): {hex(segreto_bob)[:34]}...  ← Eve lo conosce ✅")
    print()
    print("    ⚠️  ATTACCO RIUSCITO:")
    print("       Alice e Bob pensano di condividere UNO stesso segreto,")
    print("       ma in realtà ne esistono DUE DISTINTI, entrambi noti ad Eve.")
    print("       Eve può decifrare, leggere e modificare ogni messaggio.")
    print("       Il controllo di debug conferma la discrepanza tra i segreti.")
    print()
    print("    🔑 CAUSA RADICE: DH non offre alcuna autenticazione dell'identità.")
    print("       Non esiste modo per Alice di verificare che il valore ricevuto")
    print("       sia davvero la chiave pubblica di Bob e non di Eve.")
