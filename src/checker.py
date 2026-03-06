"""
Modulo avanzato per la verifica della robustezza delle password.
Include analisi dettagliata dei criteri e feedback per l'utente.
"""

import json
import re
import secrets
import string


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
    Analizza la password e restituisce il livello e la lista delle criticità.
    """
    criteria = get_password_criteria(password)
    score = 0
    missing_criteria = []

    for key, (passed, message) in criteria.items():
        if passed:
            score += 1
        else:
            missing_criteria.append(f"Mancante: {message}")

    if score <= 2:
        level = "Debole"
    elif score <= 4:
        level = "Media"
    else:
        level = "Forte"

    return level, missing_criteria


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
