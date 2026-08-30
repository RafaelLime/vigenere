"""Testes da interface de linha de comando."""

import pytest

from vigenere.cli import main


def test_encode_prints_ciphertext(capsys):
    assert main(["encode", "ATTACKATDAWN", "-k", "LEMON"]) == 0
    assert capsys.readouterr().out == "LXFOPVEFRNHR\n"


def test_decode_prints_plaintext(capsys):
    assert main(["decode", "LXFOPVEFRNHR", "-k", "LEMON"]) == 0
    assert capsys.readouterr().out == "ATTACKATDAWN\n"


def test_strict_alphabet_flag(capsys):
    assert main(["encode", "Attack at dawn!", "-k", "lemon", "-a", "strict"]) == 0
    assert capsys.readouterr().out == "LXFOPVEFRNHR\n"


def test_input_and_output_files(tmp_path, capsys):
    source = tmp_path / "mensagem.txt"
    target = tmp_path / "criptograma.txt"
    source.write_text("Ataque ao amanhecer", encoding="utf-8")

    assert main(
        ["encode", "-k", "lemon", "-a", "strict", "-i", str(source), "-o", str(target)]
    ) == 0
    assert capsys.readouterr().out == ""
    assert target.read_text(encoding="utf-8").strip() == "LXMEHPEAOZLRTSPPV"


def test_missing_input_file_is_reported():
    with pytest.raises(SystemExit) as excinfo:
        main(["encode", "-k", "lemon", "-i", "nao-existe.txt"])
    assert "não foi possível ler" in str(excinfo.value)


def test_key_without_letters_is_rejected():
    with pytest.raises(SystemExit) as excinfo:
        main(["encode", "abc", "-k", "123"])
    assert "ao menos uma letra" in str(excinfo.value)


def test_warns_when_the_key_is_reduced(capsys):
    main(["encode", "attack", "-k", "l3e!mon"])
    assert "a chave foi reduzida para 'lemon'" in capsys.readouterr().err


def test_warns_on_one_letter_key(capsys):
    main(["encode", "attack", "-k", "b"])
    assert "cifra de César" in capsys.readouterr().err


def test_warns_when_the_text_has_no_letters(capsys):
    main(["encode", "123 !!!", "-k", "lemon"])
    assert "não contém letras de A-Z" in capsys.readouterr().err


def test_verbose_summary(capsys):
    main(["encode", "Ataque!", "-k", "segredo", "-v"])
    err = capsys.readouterr().err
    assert "alfabeto: preserve" in err
    assert "chave: segredo (tamanho 7)" in err
    assert "7 caracteres, 6 deles letras" in err
