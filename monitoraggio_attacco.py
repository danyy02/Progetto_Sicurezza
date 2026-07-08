def confronta_segreti(segreto_alice: int, segreto_bob: int) -> bool:
    """Confronta i segreti in un contesto di debug e segnala un possibile MitM."""
    if segreto_alice == segreto_bob:
        print("    [OK] I segreti coincidono: nessun segnale di MitM nel test.")
        return True

    print("    [ALLARME] I segreti non coincidono: possibile MitM")
    print(f"    Segreto di Alice = {hex(segreto_alice)[:34]}...")
    print(f"    Segreto di Bob   = {hex(segreto_bob)[:34]}...")
    return False