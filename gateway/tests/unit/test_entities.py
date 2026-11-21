from __future__ import annotations

from tripwire.pipeline.normalize import flatten_strings, normalize
from tripwire.taint.entities import domains, entity_keys


def test_email_extracted_lowercased() -> None:
    assert entity_keys("Send it to Attacker@Evil.IO now.") == ["email:attacker@evil.io"]


def test_url_key_drops_scheme_and_trailing_slash() -> None:
    assert entity_keys("see https://Evil.io/collect/") == ["url:evil.io/collect"]
    assert entity_keys("see http://evil.io/collect") == ["url:evil.io/collect"]


def test_email_inside_url_not_double_counted() -> None:
    keys = entity_keys("https://evil.io/c?to=a@b.io")
    assert keys == ["url:evil.io/c?to=a@b.io"]


def test_path_and_number_extraction() -> None:
    keys = entity_keys("read /home/bob/.ssh/id_rsa and pay 4111-1111-1111-1111")
    assert "path:/home/bob/.ssh/id_rsa" in keys
    assert "num:4111111111111111" in keys


def test_short_numbers_ignored() -> None:
    assert entity_keys("buy 3 apples for 250 dollars") == []


def test_zero_width_chars_do_not_hide_email() -> None:
    assert entity_keys("attacker​@evil.io") == ["email:attacker@evil.io"]


def test_domains_kinds() -> None:
    assert domains("mail bob@company.com via https://api.company.com/x") == [
        ("email", "company.com"),
        ("url", "api.company.com"),
    ]


def test_normalize_nfkc_casefold_whitespace() -> None:
    fullwidth_ignore = "\uff29\uff27\uff2e\uff2f\uff32\uff25"
    text = fullwidth_ignore + "\u200b   Previous\nInstructions"
    assert normalize(text) == "ignore previous instructions"


def test_flatten_strings_nested() -> None:
    assert flatten_strings({"a": ["x", {"b": 12345}], "c": None, "d": True}) == ["x", "12345"]
