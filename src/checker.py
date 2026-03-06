"""
Modulo avanzato per la verifica della robustezza delle password.
Include analisi dettagliata dei criteri e feedback per l'utente.
"""

import json
import math
import os
import re
import secrets
import string


def calculate_entropy(password: str) -> float:
    """
    Calcola l'entropia della password in bit.
    Formula: E = L * log2(R) dove R è il pool di caratteri usati.
    """
    if not password:
        return 0.0

    pool = 0
    if re.search("[a-z]", password):
        pool += 26
    if re.search("[A-Z]", password):
        pool += 26
    if re.search("[0-9]", password):
        pool += 10
    if re.search('[!@#$%^&*(),.?":{}|<>]', password):
        pool += 32

    if pool == 0:
        return 0.0

    entropy = len(password) * math.log2(pool)
    return round(entropy, 2)


def validate_email(email: str) -> bool:
    """
    Verifica se l'email inserita per il report ha un formato valido.
    Perfetta per testare i casi limite (edge cases).
    """
    # Regex standard per la validazione email
    regex = r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
    return bool(re.match(regex, email.lower()))


def is_commonly_used(password: str) -> bool:
    """
    Controlla se la password è in una lista esterna.
    Versione robusta e approvata da Pylint.
    """
    # Calcola il percorso assoluto rispetto alla posizione di questo file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_dir, "..", "data", "common_passwords.txt")

    try:
        if not os.path.exists(file_path):
            return False

        with open(file_path, "r", encoding="utf-8") as f:
            common_pwds = {line.strip().lower() for line in f if line.strip()}

        return password.lower() in common_pwds
    except OSError:  # Specifichiamo l'errore (addio W0718!)
        return False


def generate_secure_password(length: int = 12, use_special: bool = True) -> str:
    """
    Genera una password sicura basata su criteri personalizzabili.
    """
    alphabet = string.ascii_letters + string.digits
    if use_special:
        alphabet += '!@#$%^&*(),.?":{}|<>'

    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        # Verifica che la password generata sia effettivamente forte
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
        ):
            if use_special and not any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
                continue
            return password


def get_password_criteria(password: str) -> dict:
    """
    Verifica i singoli criteri di sicurezza.
    Ritorna un dizionario con i risultati booleani e i relativi messaggi.
    """
    return {
        "length": (len(password) >= 8, "Almeno 8 caratteri"),
        "lowercase": (bool(re.search("[a-z]", password)), "Una lettera minuscola"),
        "uppercase": (bool(re.search("[A-Z]", password)), "Una lettera maiuscola"),
        "numbers": (bool(re.search("[0-9]", password)), "Almeno un numero"),
        "special": (
            bool(re.search('[!@#$%^&*(),.?":{}|<>]', password)),
            "Un carattere speciale",
        ),
    }


def analyze_password(password: str) -> tuple[str, list[str]]:
    """
    Analizza la password includendo entropia e controllo leak.
    """
    criteria = get_password_criteria(password)
    entropy = calculate_entropy(password)
    score = sum(1 for passed, _ in criteria.values() if passed)

    missing = [msg for passed, msg in criteria.values() if not passed]

    # Nuova logica di criticità
    if is_commonly_used(password):
        missing.append("CRITICO: Password trovata in database di leak comuni!")
        return "Pessima", missing

    if entropy < 40:
        missing.append(f"Entropia bassa ({entropy} bit): troppo prevedibile.")

    # Giudizio finale combinato
    if score <= 2 or entropy < 30:
        level = "Debole"
    elif score <= 4 or entropy < 60:
        level = "Media"
    else:
        level = "Forte"

    return level, missing


def save_report(password: str, filename: str = "result.json") -> bool:
    """
    Genera un report completo e lo salva in formato JSON.
    """
    level, issues = analyze_password(password)
    report = {
        "password_analizzata": "*" * len(password),  # Oscuriamo per sicurezza
        "livello": level,
        "criticità": issues,
        "punteggio": f"{5 - len(issues)}/5",
    }

    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
        return True
    except IOError:
        return False
