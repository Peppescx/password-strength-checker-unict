"""Unit test per il modulo src.checker."""

import pytest
from src.checker import (
    analyze_password,
    calculate_entropy,
    validate_email,
    is_commonly_used
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