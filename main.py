"""Interfaccia principale per il Password Strength Checker e Generator."""

from src.checker import analyze_password, generate_secure_password, save_report


def main():
    """Menu principale dell'applicazione."""
    print("=== Security Tool v2.0 ===")
    print("1. Analizza una password")
    print("2. Genera una password sicura")

    scelta = input("\nScegli un'opzione (1/2): ")

    if scelta == "1":
        pwd = input("Inserisci la password: ")
        livello, criticita = analyze_password(pwd)
        print(f"\nRisultato: {livello}")
        for nota in criticita:
            print(f" - {nota}")
        save_report(pwd)

    elif scelta == "2":
        try:
            lunghezza = int(input("Lunghezza desiderata (default 12): ") or 12)
            speciale = input("Includere caratteri speciali? (s/n): ").lower() == "s"
            nuova_pwd = generate_secure_password(lunghezza, speciale)
            print(f"\nPassword generata: {nuova_pwd}")
            # La analizziamo subito per conferma
            livello, _ = analyze_password(nuova_pwd)
            print(f"Grado di sicurezza: {livello}")
        except ValueError:
            print("Errore: inserisci un numero valido per la lunghezza.")

    else:
        print("Opzione non valida.")


if __name__ == "__main__":
    main()
