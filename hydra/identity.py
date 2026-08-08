"""Disposable cryptographic identity and the permanent revocation ledger.

Design rules encoded here:

* Private keys live **only** in the KeyVault, which is instantiated by the
  regeneration plane in supervisor memory. No key material is ever written
  into an execution domain, passed through its environment, or mounted into
  its filesystem. A domain therefore cannot sign anything on its own behalf --
  it can only *ask* to be quoted, exactly like an enclave asking a TPM.

* Every incarnation of a layer gets a brand-new keypair and a brand-new
  ``domain_id``. Nothing is inherited (Law 3).

* The revocation ledger is append-only and hash-chained. Once an identity is
  in it, it is untrusted forever, even if it later presents perfectly valid
  signatures (Law 4).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

try:  # pragma: no cover - exercised by whichever branch is installed
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.exceptions import InvalidSignature

    _HAVE_ED25519 = True
except Exception:  # pragma: no cover
    _HAVE_ED25519 = False


# --------------------------------------------------------------------------
# signer abstraction
# --------------------------------------------------------------------------
class _Signer:
    """Wraps whichever primitive is available. Public API is bytes in/out."""

    algo: str

    def sign(self, data: bytes) -> bytes:
        raise NotImplementedError

    def public_bytes(self) -> bytes:
        raise NotImplementedError

    @staticmethod
    def verify(public: bytes, data: bytes, sig: bytes, algo: str) -> bool:
        raise NotImplementedError


class _Ed25519Signer(_Signer):
    algo = "ed25519"

    def __init__(self):
        self._sk = Ed25519PrivateKey.generate()

    def sign(self, data: bytes) -> bytes:
        return self._sk.sign(data)

    def public_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def verify(public: bytes, data: bytes, sig: bytes, algo: str) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(sig, data)
            return True
        except (InvalidSignature, ValueError):
            return False


class _HmacSigner(_Signer):
    """Fallback when python-cryptography is unavailable.

    Symmetric, so the "public" key is really a key handle. Acceptable only
    because signer and verifier are both the supervisor root; the security
    property we are modelling (a domain cannot produce its own quote) still
    holds, because the key never leaves the vault.
    """

    algo = "hmac-sha256"
    _handles: Dict[bytes, bytes] = {}

    def __init__(self):
        self._key = secrets.token_bytes(32)
        self._handle = hashlib.sha256(b"handle" + self._key).digest()
        _HmacSigner._handles[self._handle] = self._key

    def sign(self, data: bytes) -> bytes:
        return hmac.new(self._key, data, hashlib.sha256).digest()

    def public_bytes(self) -> bytes:
        return self._handle

    @staticmethod
    def verify(public: bytes, data: bytes, sig: bytes, algo: str) -> bool:
        key = _HmacSigner._handles.get(public)
        if key is None:
            return False
        return hmac.compare_digest(hmac.new(key, data, hashlib.sha256).digest(), sig)


def _new_signer() -> _Signer:
    return _Ed25519Signer() if _HAVE_ED25519 else _HmacSigner()


def verify_signature(public: bytes, data: bytes, sig: bytes, algo: str) -> bool:
    if algo == "ed25519":
        if not _HAVE_ED25519:
            return False
        return _Ed25519Signer.verify(public, data, sig, algo)
    if algo == "hmac-sha256":
        return _HmacSigner.verify(public, data, sig, algo)
    return False


SIGNING_ALGO = "ed25519" if _HAVE_ED25519 else "hmac-sha256"


# --------------------------------------------------------------------------
# identity
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class DomainIdentity:
    """The identity of one *incarnation* of a layer. Never reused."""

    domain_id: str
    role: str
    generation: int
    public_key: str           # hex
    algo: str
    hw_serial: str            # supervisor-observed hardware binding
    born_at: float
    lineage: str              # role-scoped lineage id, stable across rebirths

    @property
    def short(self) -> str:
        return self.domain_id[:8]

    def to_dict(self):
        return asdict(self)


class KeyVault:
    """Holds every private key. Lives in the regeneration plane, host memory.

    There is intentionally no ``export``, ``get_private_key``, or serialisation
    method. The only thing callers can do is ask the vault to sign on behalf
    of a domain -- and only the attestation/regeneration planes hold a
    reference to the vault at all.
    """

    def __init__(self):
        self._signers: Dict[str, _Signer] = {}
        self._identities: Dict[str, DomainIdentity] = {}
        self._generation: Dict[str, int] = {}
        self._issued_ids: set = set()
        self._issued_keys: set = set()

    def mint(
        self,
        role: str,
        hw_serial: str,
        lineage: Optional[str] = None,
        domain_id: Optional[str] = None,
    ) -> DomainIdentity:
        signer = _new_signer()
        pub = signer.public_bytes().hex()

        domain_id = domain_id or uuid.uuid4().hex
        # Law 3 belt-and-braces: an id or key must never be reissued.
        if domain_id in self._issued_ids or pub in self._issued_keys:
            raise RuntimeError("identity collision: refusing to reissue")

        # The lineage is role-scoped so ``generation`` counts how many times
        # this role has been reborn. It carries no authority and no key
        # material -- it is a label on a tombstone, not an inheritance.
        lineage = lineage or role
        gen = self._generation.get(lineage, 0) + 1
        self._generation[lineage] = gen

        ident = DomainIdentity(
            domain_id=domain_id,
            role=role,
            generation=gen,
            public_key=pub,
            algo=signer.algo,
            hw_serial=hw_serial,
            born_at=time.time(),
            lineage=lineage,
        )
        self._signers[domain_id] = signer
        self._identities[domain_id] = ident
        self._issued_ids.add(domain_id)
        self._issued_keys.add(pub)
        return ident

    def sign_for(self, domain_id: str, data: bytes) -> bytes:
        signer = self._signers.get(domain_id)
        if signer is None:
            raise KeyError(f"no key for domain {domain_id}")
        return signer.sign(data)

    def destroy_key(self, domain_id: str) -> bool:
        """Zeroise a key. Called during Stage 5 (Revoke)."""
        return self._signers.pop(domain_id, None) is not None

    def identity(self, domain_id: str) -> Optional[DomainIdentity]:
        return self._identities.get(domain_id)

    def has_key(self, domain_id: str) -> bool:
        return domain_id in self._signers


# --------------------------------------------------------------------------
# revocation ledger
# --------------------------------------------------------------------------
@dataclass
class RevocationEntry:
    seq: int
    ts: float
    domain_id: str
    public_key: str
    hw_serial: str
    role: str
    generation: int
    reason: str
    prev_hash: str
    entry_hash: str = ""

    def compute_hash(self) -> str:
        body = {
            k: v for k, v in asdict(self).items() if k != "entry_hash"
        }
        return hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


class RevocationLedger:
    """Append-only, hash-chained tombstone list. Never supports removal.

    Law 4 lives here: ``is_revoked`` is consulted before any trust decision,
    and there is no code path that un-revokes.
    """

    GENESIS = "0" * 64

    def __init__(self, path: Optional[str] = None):
        self._entries: List[RevocationEntry] = []
        self._by_domain: Dict[str, RevocationEntry] = {}
        self._keys: set = set()
        self._serials: set = set()
        self.path = path
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            open(path, "w").close()

    @property
    def head(self) -> str:
        return self._entries[-1].entry_hash if self._entries else self.GENESIS

    def revoke(self, ident: DomainIdentity, reason: str) -> RevocationEntry:
        entry = RevocationEntry(
            seq=len(self._entries),
            ts=time.time(),
            domain_id=ident.domain_id,
            public_key=ident.public_key,
            hw_serial=ident.hw_serial,
            role=ident.role,
            generation=ident.generation,
            reason=reason,
            prev_hash=self.head,
        )
        entry.entry_hash = entry.compute_hash()
        self._entries.append(entry)
        self._by_domain[ident.domain_id] = entry
        self._keys.add(ident.public_key)
        self._serials.add(ident.hw_serial)
        if self.path:
            with open(self.path, "a") as fh:
                fh.write(json.dumps(asdict(entry), sort_keys=True) + "\n")
        return entry

    def is_revoked(
        self,
        domain_id: Optional[str] = None,
        public_key: Optional[str] = None,
        hw_serial: Optional[str] = None,
    ) -> Optional[str]:
        """Return the revocation reason if *any* supplied selector is tainted."""
        if domain_id and domain_id in self._by_domain:
            return self._by_domain[domain_id].reason
        if public_key and public_key in self._keys:
            return "revoked key material"
        if hw_serial and hw_serial in self._serials:
            return "revoked hardware binding"
        return None

    def verify_chain(self) -> bool:
        prev = self.GENESIS
        for e in self._entries:
            if e.prev_hash != prev:
                return False
            if e.compute_hash() != e.entry_hash:
                return False
            prev = e.entry_hash
        return True

    def __len__(self) -> int:
        return len(self._entries)

    def entries(self) -> List[RevocationEntry]:
        return list(self._entries)
