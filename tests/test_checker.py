"""Test unitari per verificare la logica di checker.py."""
import os
from src.checker import check_password_strength, save_result_to_json

def test_password_levels():
    """Verifica che i tre livelli di robustezza siano calcolati correttamente."""
    assert check_password_strength("123") == "Debole"
    assert check_password_strength("Password123") == "Media"
    assert check_password_strength("P@ssw0rd2026!") == "Forte"

def test_json_export():
    """Verifica che il salvataggio su file JSON funzioni."""
    test_data = {"user": "Giuseppe", "result": "Forte"}
    file_name = "test_output.json"
    
    # Esegue il test
    success = save_result_to_json(test_data, file_name)
    assert success is True
    assert os.path.exists(file_name)
    
    # Pulizia post-test
    if os.path.exists(file_name):
        os.remove(file_name)