"""The four laws, tested directly and through the cage."""

import pytest

from hydra.identity import KeyVault, RevocationLedger
from hydra.laws import (
    LawViolation,
    RegenerationAuthority,
    law1_attester_must_be_rooted,
    law1_no_self_attestation,
    law2_assert_no_leak,
    law2_no_self_regeneration,
    law3_no_identity_inheritance,
    law4_no_trust_recovery,
)


# -- Law 1 -----------------------------------------------------------------
def test_law1_rejects_self_attestation():
    with pytest.raises(LawViolation) as exc:
        law1_no_self_attestation("abc", "abc")
    assert exc.value.law == 1


def test_law1_allows_distinct_domains():
    assert law1_no_self_attestation("abc", "def").passed


def test_law1_requires_rooted_attester():
    with pytest.raises(LawViolation):
        law1_attester_must_be_rooted("stranger", {"root-a", "root-b"})
    assert law1_attester_must_be_rooted("root-a", {"root-a"}).passed


# -- Law 2 -----------------------------------------------------------------
def test_law2_rejects_missing_capability():
    real = RegenerationAuthority()
    with pytest.raises(LawViolation) as exc:
        law2_no_self_regeneration(None, real)
    assert exc.value.law == 2


def test_law2_rejects_forged_capability():
    real = RegenerationAuthority()
    forged = RegenerationAuthority()
    with pytest.raises(LawViolation):
        law2_no_self_regeneration(forged, real)


def test_law2_accepts_the_real_capability():
    real = RegenerationAuthority()
    assert law2_no_self_regeneration(real, real).passed


def test_law2_authority_never_prints_its_token():
    a = RegenerationAuthority("bmc")
    assert a.token not in repr(a)
    assert a.token not in str(a)


def test_law2_leak_detection():
    a = RegenerationAuthority()
    assert law2_assert_no_leak(a, [b"harmless", b"also fine"]).passed
    with pytest.raises(LawViolation):
        law2_assert_no_leak(a, [b"prefix" + a.token.encode() + b"suffix"])


# -- Law 3 -----------------------------------------------------------------
def test_law3_rejects_reused_identity():
    vault = KeyVault()
    old = vault.mint("containment", "hw-1")
    with pytest.raises(LawViolation) as exc:
        law3_no_identity_inheritance(old, [old])
    assert exc.value.law == 3


def test_law3_rejects_reused_hardware_binding():
    vault = KeyVault()
    old = vault.mint("containment", "hw-1")
    clone = vault.mint("containment", "hw-1")  # same serial, new keys
    with pytest.raises(LawViolation):
        law3_no_identity_inheritance(clone, [old])


def test_law3_accepts_a_genuinely_fresh_identity():
    vault = KeyVault()
    old = vault.mint("containment", "hw-1")
    new = vault.mint("containment", "hw-2")
    assert law3_no_identity_inheritance(new, [old]).passed
    assert new.generation == old.generation + 1
    assert new.public_key != old.public_key
    assert new.domain_id != old.domain_id


# -- Law 4 -----------------------------------------------------------------
def test_law4_blocks_revoked_identity_forever():
    vault, ledger = KeyVault(), RevocationLedger()
    ident = vault.mint("containment", "hw-1")
    assert law4_no_trust_recovery(ledger, domain_id=ident.domain_id).passed
    ledger.revoke(ident, "compromised")
    for selector in ("domain_id", "public_key", "hw_serial"):
        with pytest.raises(LawViolation) as exc:
            law4_no_trust_recovery(ledger, **{selector: getattr(ident, selector)})
        assert exc.value.law == 4


def test_law4_ledger_has_no_unrevoke_api():
    ledger = RevocationLedger()
    forbidden = {"unrevoke", "remove", "delete", "pop", "clear", "restore"}
    assert forbidden.isdisjoint(dir(ledger))


def test_revocation_chain_detects_mutation():
    vault, ledger = KeyVault(), RevocationLedger()
    for i in range(3):
        ledger.revoke(vault.mint("containment", f"hw-{i}"), f"reason {i}")
    assert ledger.verify_chain()
    ledger.entries()[1].reason = "cleared"
    assert not ledger.verify_chain()


# -- Key vault -------------------------------------------------------------
def test_vault_exposes_no_private_key():
    vault = KeyVault()
    ident = vault.mint("containment", "hw-1")
    for name in ("export", "private_key", "get_private_key", "secret", "keys"):
        assert not hasattr(vault, name)
    assert vault.sign_for(ident.domain_id, b"data")
    vault.destroy_key(ident.domain_id)
    with pytest.raises(KeyError):
        vault.sign_for(ident.domain_id, b"data")
