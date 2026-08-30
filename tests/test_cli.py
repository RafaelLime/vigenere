"""Tests for the command-line interface."""

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
    source = tmp_path / "plain.txt"
    target = tmp_path / "cipher.txt"
    source.write_text("Ataque ao amanhecer", encoding="utf-8")

    assert main(
        ["encode", "-k", "lemon", "-a", "strict", "-i", str(source), "-o", str(target)]
    ) == 0
    assert capsys.readouterr().out == ""
    assert target.read_text(encoding="utf-8").strip() == "LXMEHPEAOZLRTSPPV"


def test_missing_input_file_is_reported():
    with pytest.raises(SystemExit) as excinfo:
        main(["encode", "-k", "lemon", "-i", "does-not-exist.txt"])
    assert "cannot read" in str(excinfo.value)


def test_key_without_letters_is_rejected():
    with pytest.raises(SystemExit) as excinfo:
        main(["encode", "abc", "-k", "123"])
    assert "at least one letter" in str(excinfo.value)


def test_warns_when_the_key_is_reduced(capsys):
    main(["encode", "attack", "-k", "l3e!mon"])
    assert "the key was reduced to 'lemon'" in capsys.readouterr().err


def test_warns_on_one_letter_key(capsys):
    main(["encode", "attack", "-k", "b"])
    assert "Caesar cipher" in capsys.readouterr().err


def test_warns_when_the_text_has_no_letters(capsys):
    main(["encode", "123 !!!", "-k", "lemon"])
    assert "no A-Z letters" in capsys.readouterr().err


def test_verbose_summary(capsys):
    main(["encode", "Ataque!", "-k", "segredo", "-v"])
    err = capsys.readouterr().err
    assert "alphabet: preserve" in err
    assert "key: segredo (length 7)" in err
    assert "7 characters, 6 of them letters" in err
