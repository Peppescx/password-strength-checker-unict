from src.checker import (
    analyze_password,
    calculate_entropy,
    generate_secure_password,
    save_report,
    validate_email,
    get_strength_bar
)


def main():
    """Menu principale dell'applicazione."""
    print("=== Security Tool v2.0 ===")
    print("1. Analizza una password")
    print("2. Genera una password sicura")
    print("3. Esci")

    scelta = input("\nScegli un'opzione (1/2/3): ")

    if scelta == "1":
        pwd = input("Inserisci la password da analizzare: ")

        # Calcolo entropia e analisi
        entropia = calculate_entropy(pwd)
        livello, criticita = analyze_password(pwd)
        strength_bar = get_strength_bar(pwd)

        print("\n--- Analisi Sicurezza ---")
        print(f"Livello: {livello}")
        print(f"Forza password: {strength_bar}")
        print(f"Entropia: {entropia} bit")

        if criticita:
            print("Criticità riscontrate:")
            for nota in criticita:
                print(f" [!] {nota}")
        else:
            print(" [+] Nessuna criticità rilevata.")

        # Richiesta email per il report con validazione
        email = input("\nInserisci la tua email per il report: ")
        if validate_email(email):
            if save_report(pwd):
                print(f"Report salvato con successo per l'utente: {email}")
            else:
                print("Errore durante il salvataggio del file JSON.")
        else:
            print("Email non valida. Il report non verrà salvato con metadati utente.")

    elif scelta == "2":
        try:
            lunghezza = int(input("Lunghezza desiderata (default 12, min 8): ") or 12)
            if lunghezza < 1:
                print("Lunghezza non valida, imposto default a 12.")
                lunghezza = 12

            speciale = input("Includere caratteri speciali? (s/n): ").lower() == "s"
            nuova_pwd = generate_secure_password(lunghezza, speciale)

            print(f"\nPassword generata: {nuova_pwd}")
            livello, _ = analyze_password(nuova_pwd)
            print(f"Grado di sicurezza stimato: {livello}")

        except ValueError:
            print("Errore: inserisci un numero intero per la lunghezza.")

    elif scelta == "3":
        print("Chiusura del programma. Stay safe!")
    else:
        print("Opzione non valida.")


if __name__ == "__main__":
    main()
    
