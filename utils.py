def separatore(titolo: str) -> None:
    """Stampa un'intestazione visiva per separare i tre scenari."""
    larghezza = 68
    print()
    print("=" * larghezza)
    print(f"  {titolo}")
    print("=" * larghezza)

def passo(numero: int, descrizione: str) -> None:
    """Stampa un passo numerato all'interno di uno scenario."""
    print(f"\n  [Passo {numero}] {descrizione}")
    print("  " + "-" * 60)
