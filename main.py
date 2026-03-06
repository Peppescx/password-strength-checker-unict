"""
Punto di ingresso principale dell'applicazione Password Strength Checker.
"""

from src.checker import check_password_strength, save_result_to_json


def main():
    """Funzione principale per l'interazione con l'utente."""
    print("=== Password Strength Checker ===")

    # 1. Input dell'utente
    password = input("Inserisci la password da analizzare: ")

    # 2. Elaborazione tramite il modulo in src/
    risultato = check_password_strength(password)

    # 3. Output a video
    print(f"\nLa robustezza della password è: {risultato}")

    # 4. Esempio di esportazione (opzionale)
    dati_da_salvare = {"password_inserita": password, "livello_robustezza": risultato}

    if save_result_to_json(dati_da_salvare):
        print("Risultato salvato correttamente in 'result.json'.")
    else:
        print("Errore durante il salvataggio del file.")


if __name__ == "__main__":
    main()
