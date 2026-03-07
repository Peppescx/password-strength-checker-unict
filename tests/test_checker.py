"""Unit test per il modulo src.checker."""

import os

from src.checker import (
    analyze_password,
    calculate_entropy,
    generate_secure_password,
    is_commonly_used,
    save_report,
    validate_email,
    get_strength_bar
)


def test_analyze_password():
    """Testa il giudizio sulla robustezza."""
    livello, _ = analyze_password("PasswordSicura123!")
    assert livello == "Forte"


def test_calculate_entropy():
    """Testa il calcolo dell'entropia."""
    # Password corta solo minuscole = entropia bassa
    assert calculate_entropy("abc") < 20
    # Password complessa = entropia alta
    assert calculate_entropy("A1!b2C3#d4E5") > 50


def test_validate_email():
    """Testa la validazione delle email."""
    assert validate_email("test@unict.it") is True
    assert validate_email("email_errata.it") is False


def test_is_commonly_used():
    """Testa il rilevamento di password comuni."""
    # Questo funzionerà se hai creato data/common_passwords.txt
    assert is_commonly_used("123456") is True
    assert is_commonly_used("UnaPasswordMoltoRara2026!") is False


def test_generate_password_variants():
    """Testa la generazione con e senza caratteri speciali."""
    pwd1 = generate_secure_password(length=16, use_special=True)
    assert len(pwd1) == 16

    pwd2 = generate_secure_password(length=8, use_special=False)
    assert len(pwd2) == 8


def test_analyze_levels():
    """Testa tutti i rami della funzione analyze_password (per la Coverage)."""
    # Caso Debole
    liv, _ = analyze_password("123")
    assert liv == "Debole"

    # Caso Media - Usiamo una password NON comune (es. aggiungendo un prefisso raro)
    # "Password123" è nei leak, "Rara_Password_2026" probabilmente no.
    liv, _ = analyze_password("Zyx_98765")
    assert liv == "Media"

    # Caso Forte
    liv, _ = analyze_password("Complessa_!@_99_Z")
    assert liv == "Forte"


def test_save_report_execution():
    """Testa il salvataggio fisico del file JSON."""
    test_file = "test_result.json"
    result = save_report("TestPassword123!", filename=test_file)
    assert result is True
    assert os.path.exists(test_file)
    # Pulizia dopo il test
    if os.path.exists(test_file):
        os.remove(test_file)
        
def test_strength_bar_weak():
    """Verifica che una password debole produca una barra con blocchi vuoti"""
    strength_bar = get_strength_bar("abc")
    assert "░" in strength_bar  
    
def test_strength_bar_strong():
    """Verifica che una password forte produca una barra con blocchi pieni"""
    strength_bar = get_strength_bar("Complessa_!@_99_Z")
    assert "█" in strength_bar
    
def test_strength_bar_format():
    """Verifica che l'output contenga una percentuale"""
    strength_bar = get_strength_bar("Password123!")
    assert "%" in strength_bar
    
    
    
