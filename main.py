"""
Punto di ingresso principale dell'applicazione Password Strength Checker.
"""

from src.checker import analyze_password, save_result_to_json


def main():
    """Funzione principale per l'interazione con l'utente."""
    print("=== Password Strength Checker ===")

    # 1. Input dell'utente
    password = input("Inserisci la password da analizzare: ")

    # 2. Elaborazione (spacchettiamo la tupla: livello e lista criticità)
    livello, criticita = analyze_password(password)

    # 3. Output a video con formattazione dell'array
    print(f"\nLa robustezza della password è: {livello}")

    if criticita:
        print("Suggerimenti per migliorare la sicurezza:")
        for nota in criticita:
            print(f" - {nota}")
    else:
        print("Ottimo! La password rispetta tutti i criteri.")

    # 4. Esportazione tramite la nuova funzione save_report
    if save_result_to_json(password):
        print("\nReport completo salvato correttamente in 'result.json'.")
    else:
        print("\nErrore durante il salvataggio del report.")


if __name__ == "__main__":
    main()
