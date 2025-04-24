# Klever Blockchain Certificate Issuance

Klever Blockchain Certificate Issuance is a smart contract designed to enable trusted, tamper-proof issuance, verification, and revocation of digital certificates on the Klever Blockchain. The contract supports advanced cryptographic features for secure and privacy-preserving attribute verification.

## 🔐 Key Features

- **Certificate Issuance:** Authorized issuers can generate certificates, store their hashed metadata in Merkle Trees, and anchor the Merkle root on-chain.
- **On-Chain Verification:** Anyone can verify the authenticity and validity of a certificate using its unique ID.
- **Revocation Mechanism:** Certificates can be revoked by the issuer, and this status is reflected on-chain.
- **Audit Trail:** Every issuance and revocation emits an event with a timestamp, enabling complete traceability.
- **Zero-Knowledge Proof Verification:** Validate certificates without disclosing sensitive information using ZKPs.
- **Selective Disclosure:** Verify specific attributes (e.g., graduation date, degree type) using privacy-preserving proofs.

## 📦 Smart Contract Architecture

### Data Structures

```rust
struct Certificate {
    certificate_id: [u8; 32],
    issuance_date: u64,
    expiration_date: u64,
    revoked_date: u64,
    merkle_root: [u8; 32],
}

struct CertificateEvents {
    issuance_date: u64,
    expiration_date: u64,
    revoked_date: u64,
}

struct Leaf {
    hash: [u8; 32],
    salt: [u8; 32],
}
```

- Each certificate is uniquely identified by a `certificate_id`.
- Certificates store issuance, expiration, revocation timestamps and the Merkle root of their fields.

### Constants

- `MAX_LEAVES = 32` – Maximum number of fields (leaves) per certificate.
- `BATCH_SIZE = 32` – Hash size for each leaf in bytes.

## 📜 Available Endpoints

### `create`

```rust
#[only_owner]
#[endpoint]
fn create(&self, expiration_date: u64, salt: [u8; 32], hashes: &[u8]) -> [u8; 32]
```

Creates a new certificate by:
- Hashing its attributes.
- Generating a Merkle root.
- Storing it on-chain.

**Parameters:**
- `expiration_date`: Optional expiration timestamp (0 for no expiration).
- `salt`: Cryptographic salt used for hashing.
- `hashes`: Concatenated byte array of all 32-byte field hashes.

**Returns:** Unique `certificate_id`.

---

### `revoke`

```rust
#[only_owner]
#[endpoint]
fn revoke(&self, certificate_id: [u8; 32])
```

Revokes a certificate by updating its on-chain record.

---

### `change_expiration_date`

```rust
#[only_owner]
#[endpoint]
fn change_expiration_date(&self, certificate_id: [u8; 32], expiration_date: u64)
```

Modifies the expiration date of an existing certificate.

---

### `check`

```rust
#[view]
fn check(&self, certificate_id: [u8; 32]) -> bool
```

Checks the validity of a certificate. Returns `false` if the certificate is expired or revoked.

---

### `get_certificate_events`

```rust
#[view]
fn get_certificate_events(&self, certificate_id: [u8; 32]) -> CertificateEvents
```

Fetches timestamps related to issuance, expiration, and revocation.

---

### `proof`

```rust
#[view]
fn proof(&self, certificate_id: [u8; 32], salt: [u8; 32], data: &[u8]) -> bool
```

Verifies whether a specific attribute (hash) is part of a certificate’s Merkle tree using a Zero-Knowledge Proof approach.

**Parameters:**
- `certificate_id`: ID of the certificate.
- `salt`: Salt used during hashing.
- `data`: The attribute data hash (32 bytes) to be verified.

---

## 🔐 Cryptographic Design

### Merkle Tree Construction

- Certificates are structured using Merkle trees to represent their attributes.
- The contract builds and stores Merkle trees deterministically, enabling efficient inclusion proofs.

### Zero-Knowledge Proof Integration

- Proof generation is based on Merkle path inclusion.
- Attributes can be privately verified without revealing the entire certificate content.

## 📊 Events

- `issue`: Emitted upon certificate creation.
- `revoke`: Emitted upon certificate revocation.
- `change_expiration_date`: Emitted when a certificate’s expiration is updated.

---

## 🧪 Testing & Deployment

### Prerequisites

- [KleverChain SDK](https://docs.klever.org/introduction-to-kleverchain-sdk)
- Rust-based Smart Contract development environment
- [Klever IDE](https://marketplace.visualstudio.com/items?itemName=Klever-org.vscode-kvm-ide) or CLI for deployment

### Deployment

1. Compile the smart contract using Klever IDE or CLI.
2. Deploy it to KleverChain Testnet/Mainnet (Only available on Testnet).
3. Use the endpoint functions via [KleverScan](https://testnet.kleverscan.org/) or dApp frontend.

---

## 🛡 Security Notes

- Only contract owners can create, revoke, or update certificates.
- Merkle tree and hashing mechanisms prevent tampering or duplication.
- Salted hashing ensures unique leaf nodes even with duplicate values.

---

## 📬 Contact

For more information, reach out to the Klever Blockchain developer team or open a discussion in the [Klever Forum](https://forum.klever.org/c/kleverchain/developers/9)
