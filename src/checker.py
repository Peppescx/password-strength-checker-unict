"""
Modulo per la verifica della robustezza delle password.
Fornisce funzioni per analizzare i criteri di sicurezza e esportare i risultati.
"""

import re
import json


def check_password_strength(password: str) -> str:
    """
    Analizza una stringa e restituisce il livello di robustezza.
    Criteri: Lunghezza, Minuscole, Maiuscole, Numeri, Caratteri Speciali.
    """
    score = 0
    if len(password) >= 8:
        score += 1
    if re.search("[a-z]", password):
        score += 1
    if re.search("[A-Z]", password):
        score += 1
    if re.search("[0-9]", password):
        score += 1
    if re.search('[!@#$%^&*(),.?":{}|<>]', password):
        score += 1

    if score <= 2:
        return "Debole"
    if score <= 4:
        return "Media"
    return "Forte"


def save_result_to_json(result_data: dict, filename: str = "result.json") -> bool:
    """Salva il dizionario dei risultati in un file JSON."""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(result_data, f, indent=4)
        return True
    except IOError:
        return False
