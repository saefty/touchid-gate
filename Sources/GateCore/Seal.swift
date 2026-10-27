import CryptoKit
import Foundation

/// One Secure Enclave key per store; only its wrapped blob and public half are on disk.
/// `macPeer` is the public half of a throwaway key whose private half was discarded at
/// init: ECDH(SE key, macPeer) is computed by the Secure Enclave, for any process that holds
/// the .enclave-key blob and gets one approval.
public struct StoreKey: Codable {
    public var seKey: Data
    public var publicKey: Data
    public var macPeer: Data?
    /// The access-control policy the SE key was created with; a key file without it is refused.
    public var policy: Policy?

    public init(seKey: Data, publicKey: Data, macPeer: Data?, policy: Policy? = nil) {
        self.seKey = seKey
        self.publicKey = publicKey
        self.macPeer = macPeer
        self.policy = policy
    }

    /// What the config pins: a swapped key, macPeer or edited policy changes it.
    public var fingerprint: String? {
        guard let macPeer else { return nil }
        var data = publicKey + macPeer
        if let policy { data += Data(policy.rawValue.utf8) }
        return "sha256:" + SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

public func newMacPeer() -> Data { P256.KeyAgreement.PrivateKey().publicKey.x963Representation }

/// ECIES box for one entry: fresh ephemeral P-256 key + AES-GCM (nonce‖ciphertext‖tag),
/// plus an HMAC keyed by the Secure Enclave (see StoreKey). Anyone with the public key can encrypt,
/// so without the MAC an attacker could plant entries (e.g. a token for their own account).
public struct Box: Codable {
    public var ephemeral: Data
    public var sealed: Data
    public var mac: Data?
}

/// Secure Enclave key in the executable, software key in selftest.
public protocol KeyAgreementKey {
    func sharedSecret(with publicKey: P256.KeyAgreement.PublicKey) throws -> SharedSecret
}

extension P256.KeyAgreement.PrivateKey: KeyAgreementKey {
    public func sharedSecret(with publicKey: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        try sharedSecretFromKeyAgreement(with: publicKey)
    }
}

// box encryption: format v1; changing this breaks existing stores
func boxKey(_ secret: SharedSecret, ephemeral: Data, name: String) -> SymmetricKey {
    // the entry name is bound so a box cannot be replayed under another entry
    secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeral,
                                   sharedInfo: Data("touchid-gate pass v1 \(name)".utf8),
                                   outputByteCount: 32)
}

/// Static until the next init: one leaked ECDH(SE key, macPeer) forges entries until then.
public func macKey(_ key: KeyAgreementKey, peer: Data) throws -> SymmetricKey {
    let secret = try key.sharedSecret(with: P256.KeyAgreement.PublicKey(x963Representation: peer))
    return secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data("touchid-gate mac v2".utf8),
                                          sharedInfo: peer, outputByteCount: 32)
}

func macInput(_ box: Box, name: String) -> Data {
    // names come from argv and cannot contain NUL; the ephemeral key has a fixed length
    Data("touchid-gate mac v2\u{0}\(name)\u{0}".utf8) + box.ephemeral + box.sealed
}

/// Encryption needs only the public key; the MAC key needs the SE blob and one approval.
public func seal(_ plain: Data, to publicKey: Data, name: String, mac: SymmetricKey) throws -> Box {
    let recipient = try P256.KeyAgreement.PublicKey(x963Representation: publicKey)
    let ephemeral = P256.KeyAgreement.PrivateKey()
    let secret = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
    let eph = ephemeral.publicKey.x963Representation
    let sealed = try AES.GCM.seal(plain, using: boxKey(secret, ephemeral: eph, name: name)).combined!
    var box = Box(ephemeral: eph, sealed: sealed, mac: nil)
    box.mac = Data(HMAC<SHA256>.authenticationCode(for: macInput(box, name: name), using: mac))
    return box
}

/// Verifies the MAC before decrypting; entries without one are refused.
public func openBox(_ box: Box, with key: KeyAgreementKey, name: String, mac: SymmetricKey) throws -> Data {
    guard let tag = box.mac else { throw GateError("\(name) has no MAC; refusing it, log in again") }
    // macInput relies on the fixed-length x963 point to separate ephemeral from sealed
    guard box.ephemeral.count == 65 else { throw GateError("\(name) has a malformed ephemeral key; refusing") }
    guard HMAC<SHA256>.isValidAuthenticationCode(tag, authenticating: macInput(box, name: name), using: mac) else {
        throw GateError("\(name) failed authentication; refusing a forged or tampered entry")
    }
    let secret = try key.sharedSecret(with: P256.KeyAgreement.PublicKey(x963Representation: box.ephemeral))
    return try AES.GCM.open(AES.GCM.SealedBox(combined: box.sealed),
                            using: boxKey(secret, ephemeral: box.ephemeral, name: name))
}
