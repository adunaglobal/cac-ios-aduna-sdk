//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  certificates.swift
//  aduna-sdk
//

import Foundation
import CryptoKit
import Security

struct CertIdentity: Hashable {
    let dns: String
    let sha256Fingerprint: String

    init(dns: String, sha256Fingerprint: String) {
        self.dns = dns.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        self.sha256Fingerprint = CertIdentity.canonicalizeFingerprint(sha256Fingerprint)
    }

    static func canonicalizeFingerprint(_ fp: String) -> String {
        // Remove non-hex, then uppercase and re-colonize every 2 chars.
        let hexOnly = fp
            .uppercased()
            .filter { ("0"..."9").contains($0) || ("A"..."F").contains($0) }
        var out: [String] = []
        out.reserveCapacity(hexOnly.count / 2)
        var i = hexOnly.startIndex
        while i < hexOnly.endIndex {
            let j = hexOnly.index(i, offsetBy: 2, limitedBy: hexOnly.endIndex) ?? hexOnly.endIndex
            out.append(String(hexOnly[i..<j]))
            i = j
        }
        return out.joined(separator: ":")
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(dns)
        hasher.combine(sha256Fingerprint) 
    }

    static func == (lhs: CertIdentity, rhs: CertIdentity) -> Bool {
        lhs.dns.caseInsensitiveCompare(rhs.dns) == .orderedSame &&
        lhs.sha256Fingerprint == rhs.sha256Fingerprint
    }
}

// MARK: - DistinguishedName
struct DistinguishedName {
    struct Attribute {
        let oid: String
        let value: String
    }
    var attributes: [Attribute] = []
    
    init(attributes: [Attribute]) {
        self.attributes = attributes
    }
    
    init(@DistinguishedNameBuilder _ builder: () -> [Attribute]) {
        self.attributes = builder()
    }
}

@resultBuilder
enum DistinguishedNameBuilder {
    static func buildBlock(_ components: DistinguishedName.Attribute...) -> [DistinguishedName.Attribute] {
        components
    }
}

func CommonName(_ value: String) -> DistinguishedName.Attribute {
    .init(oid: "2.5.4.3", value: value)
}
func OrganizationName(_ value: String) -> DistinguishedName.Attribute {
    .init(oid: "2.5.4.10", value: value)
}
func CountryName(_ value: String) -> DistinguishedName.Attribute {
    .init(oid: "2.5.4.6", value: value)
}

// MARK: - Extensions
enum CertificateExtension {
    case basicConstraints(isCA: Bool, critical: Bool = true)
    case keyUsage(digitalSignature: Bool, critical: Bool = true)
}

struct CertificateExtensions {
    var items: [CertificateExtension] = []
    init(@ExtensionsBuilder _ builder: () -> [CertificateExtension]) {
        self.items = builder()
    }
}

@resultBuilder
enum ExtensionsBuilder {
    static func buildBlock(_ components: CertificateExtension...) -> [CertificateExtension] {
        components
    }
}

func Critical(_ ext: CertificateExtension) -> CertificateExtension {
    return ext
}

func BasicConstraints(notCertificateAuthority: Bool) -> CertificateExtension {
    .basicConstraints(isCA: !notCertificateAuthority)
}
func KeyUsage(digitalSignature: Bool) -> CertificateExtension {
    .keyUsage(digitalSignature: digitalSignature)
}

// MARK: - Certificate
struct Certificate {
    enum Version: Int {
        case v3 = 2
    }
    
    struct SerialNumber {
        let value: Data
        init() {
            var bytes = [UInt8](repeating: 0, count: 16)
            _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
            // Ensure positive INTEGER (MSB must be 0); prefix 0x00 if needed
            if bytes.first.map({ $0 & 0x80 != 0 }) == true {
                self.value = Data([0x00]) + Data(bytes)
            } else {
                self.value = Data(bytes)
            }
        }
    }

    struct PublicKey {
        let x963Representation: Data
        init(_ key: P256.Signing.PublicKey) {
            self.x963Representation = key.x963Representation
        }
    }
    
    struct PrivateKey {
        let secKey: SecKey
        init(_ secKey: SecKey) throws {
            self.secKey = secKey
        }
    }
    
    let version: Version
    let serialNumber: SerialNumber
    let publicKey: PublicKey
    let notValidBefore: Date
    let notValidAfter: Date
    let issuer: DistinguishedName
    let subject: DistinguishedName
    let extensions: CertificateExtensions
    let issuerPrivateKey: PrivateKey
    
    init(
        version: Version,
        serialNumber: SerialNumber,
        publicKey: PublicKey,
        notValidBefore: Date,
        notValidAfter: Date,
        issuer: DistinguishedName,
        subject: DistinguishedName,
        extensions: CertificateExtensions,
        issuerPrivateKey: PrivateKey
    ) {
        self.version = version
        self.serialNumber = serialNumber
        self.publicKey = publicKey
        self.notValidBefore = notValidBefore
        self.notValidAfter = notValidAfter
        self.issuer = issuer
        self.subject = subject
        self.extensions = extensions
        self.issuerPrivateKey = issuerPrivateKey
    }
    
    func serializeAsDER() throws -> Data {
        // 1) Build Name (issuer/subject)
        let issuerDER  = ASN1.Name.encode(rdnAttributes: issuer.attributes)
        let subjectDER = ASN1.Name.encode(rdnAttributes: subject.attributes)

        // 2) Validity
        let validityDER = ASN1.sequence([
            ASN1.timeUTC(notValidBefore),
            ASN1.timeUTC(notValidAfter)
        ])

        // 3) SubjectPublicKeyInfo (algorithm + key)
        let spki = ASN1.sequence([
            ASN1.sequence([
                ASN1.oid(.ecPublicKey),
                ASN1.oid(.prime256v1)
            ]),
            ASN1.bitString(publicKey.x963Representation) // 0 unused bits prefixed inside
        ])

        // 4) v3 Extensions (critical basicConstraints CA=false, keyUsage digitalSignature)
        let extSequence = ASN1.sequence(extensions.items.map { ext in
            switch ext {
            case .basicConstraints(let isCA, let critical):
                // Value: SEQUENCE { cA BOOLEAN DEFAULT FALSE }
                // For CA=false we still encode BOOLEAN FALSE for clarity.
                let valueDER = ASN1.sequence([ ASN1.boolean(isCA) ])
                return ASN1.sequence([
                    ASN1.oid(.basicConstraints),
                    critical ? ASN1.boolean(true) : nil,
                    ASN1.octetString(valueDER)
                ].compactMap { $0 })

            case .keyUsage(let digitalSignature, let critical):
                // KeyUsage BIT STRING: bit0=digitalSignature
                var bits = [UInt8](repeating: 0, count: 1)
                if digitalSignature { bits[0] |= 0b1000_0000 >> 0 } // bit 0 set
                // Encode as DER BIT STRING containing those bits (with 0 unused)
                let bitString = ASN1.bitString(Data(bits))
                return ASN1.sequence([
                    ASN1.oid(.keyUsage),
                    critical ? ASN1.boolean(true) : nil,
                    ASN1.octetString(bitString)
                ].compactMap { $0 })
            }
        })

        // Extensions are part of TBSCertificate as [3] EXPLICIT
        let tbs = ASN1.sequence([
            ASN1.contextExplicit(0, ASN1.integer(fromInt: version.rawValue)), // version=v3
            ASN1.integer(serialNumber.value),
            ASN1.signatureAlgorithmIdentifier, // ecdsa-with-SHA256 (no params)
            issuerDER,
            validityDER,
            subjectDER,
            spki,
            ASN1.contextExplicit(3, extSequence)
        ])

        // 5) Sign TBS with SecKey (ECDSA w/ SHA256)
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(
            issuerPrivateKey.secKey,
            .ecdsaSignatureMessageX962SHA256, // hashes internally with SHA256
            tbs as CFData,
            &error
        ) as Data? else {
            throw error?.takeRetainedValue() ?? NSError(domain: "MinimalCertificates", code: -1, userInfo: [NSLocalizedDescriptionKey: "Signature failed"])
        }

        // 6) Certificate := SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        let cert = ASN1.sequence([
            tbs,
            ASN1.signatureAlgorithmIdentifier, // same alg id as TBSCertificate
            ASN1.bitString(sig) // X9.62 DER (SEQUENCE { r, s }) wrapped in BIT STRING
        ])

        return cert
    }
}

// MARK: - ASN.1 Minimal Helpers (DER)

private enum ASN1 {
    // Common OIDs we use
    enum OID {
        case ecPublicKey            // 1.2.840.10045.2.1
        case prime256v1            // 1.2.840.10045.3.1.7
        case ecdsaWithSHA256       // 1.2.840.10045.4.3.2
        case basicConstraints      // 2.5.29.19
        case keyUsage              // 2.5.29.15
        case subjectAltName        // 2.5.29.17
        case countryName           // 2.5.4.6
        case organizationName      // 2.5.4.10
        case commonName            // 2.5.4.3

        var bytes: [UInt8] {
            switch self {
            case .ecPublicKey:      return [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
            case .prime256v1:       return [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
            case .ecdsaWithSHA256:  return [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]
            case .basicConstraints: return [0x55, 0x1D, 0x13]
            case .keyUsage:         return [0x55, 0x1D, 0x0F]
            case .subjectAltName:   return [0x55, 0x1D, 0x11]
            case .countryName:      return [0x55, 0x04, 0x06]
            case .organizationName: return [0x55, 0x04, 0x0A]
            case .commonName:       return [0x55, 0x04, 0x03]
            }
        }
    }

    // AlgorithmIdentifier for ecdsa-with-SHA256 (parameters ABSENT per RFC 5758)
    static var signatureAlgorithmIdentifier: Data {
        sequence([ oid(.ecdsaWithSHA256) ])
    }

    // Name (SEQUENCE of RDN SETs). We encode each attribute as SET { SEQUENCE { oid, value } }.
    enum Name {
        static func encode(rdnAttributes: [DistinguishedName.Attribute]) -> Data {
            // Preserve provided order; common is C, O, CN, but it’s not critical.
            let rdnSeq = rdnAttributes.map { attr -> Data in
                let valueDER: Data
                // Country should be PrintableString (2 letters); others UTF8String.
                if attr.oid == "2.5.4.6" { // C
                    valueDER = printableString(attr.value)
                } else {
                    valueDER = utf8String(attr.value)
                }
                let oidDER = oid(fromString: attr.oid)
                return set([ sequence([ oidDER, valueDER ]) ])
            }
            return sequence(rdnSeq)
        }
    }

    // ---- Primitives / Constructors ----

    static func integer(_ bytes: Data) -> Data {
        // Ensure minimal, positive INTEGER encoding: prefix 0x00 if MSB set
        let body: Data
        if bytes.first.map({ $0 & 0x80 != 0 }) == true { body = Data([0x00]) + bytes } else { body = bytes }
        return tag(0x02, body)
    }
    static func integer(fromInt v: Int) -> Data {
        var be = withUnsafeBytes(of: Int64(v).bigEndian, Array.init)
        while be.first == 0 && be.count > 1 { be.removeFirst() }
        return integer(Data(be))
    }

    static func boolean(_ value: Bool) -> Data {
        tag(0x01, Data([value ? 0xFF : 0x00]))
    }

    static func null() -> Data { Data([0x05, 0x00]) }

    static func oid(_ oid: OID) -> Data { tag(0x06, Data(oid.bytes)) }

    static func oid(fromString dotted: String) -> Data {
        // Minimal mapper for the DNs we support, else fallback if needed
        switch dotted {
        case "2.5.4.3":  return oid(.commonName)
        case "2.5.4.6":  return oid(.countryName)
        case "2.5.4.10": return oid(.organizationName)
        default:
            // Not expected in this minimal build; you can extend if needed.
            // A full generic OID encoder is out of scope here.
            return oid(.commonName) // safe default, but better to extend mapping.
        }
    }

    static func utf8String(_ s: String) -> Data {
        let data = Data(s.utf8)
        return tag(0x0C, data)
    }

    static func printableString(_ s: String) -> Data {
        let data = Data(s.utf8) // assuming valid printable ASCII for country
        return tag(0x13, data)
    }

    static func generalizedTime(_ date: Date) -> Data {
        // Not used here (we use UTCTime up to 2049)
        let f = DateFormatter()
        f.timeZone = TimeZone(secondsFromGMT: 0)
        f.dateFormat = "yyyyMMddHHmmss'Z'"
        let bytes = Array(f.string(from: date).utf8)
        return tag(0x18, Data(bytes))
    }

    static func timeUTC(_ date: Date) -> Data {
        let f = DateFormatter()
        f.timeZone = TimeZone(secondsFromGMT: 0)
        f.dateFormat = "yyMMddHHmmss'Z'"
        let bytes = Array(f.string(from: date).utf8)
        return tag(0x17, Data(bytes))
    }

    static func octetString(_ body: Data) -> Data { tag(0x04, body) }

    static func bitString(_ body: Data) -> Data {
        // Prefix with "unused bits" count = 0
        tag(0x03, Data([0x00]) + body)
    }

    static func sequence(_ elements: [Data]) -> Data {
        tagConstructed(0x10, concat(elements))
    }

    static func set(_ elements: [Data]) -> Data {
        tagConstructed(0x11, concat(elements))
    }

    static func contextExplicit(_ number: UInt8, _ inner: Data) -> Data {
        // [n] EXPLICIT: tag class=CONTEXT (10), constructed, tag number n
        let tagByte: UInt8 = 0xA0 | (number & 0x1F)
        return tag(tagByte, inner)
    }

    // ---- Tag + Length helpers ----

    private static func tag(_ tag: UInt8, _ body: Data) -> Data {
        var out = Data([tag])
        out.append(encodeLength(body.count))
        out.append(body)
        return out
    }

    private static func tagConstructed(_ base: UInt8, _ body: Data) -> Data {
        // constructed flag (bit 6) set
        return tag(0x20 | base, body)
    }

    private static func encodeLength(_ len: Int) -> Data {
        if len < 128 { return Data([UInt8(len)]) }
        var bytes = withUnsafeBytes(of: UInt32(len).bigEndian, Array.init)
        while bytes.first == 0 { bytes.removeFirst() }
        return Data([0x80 | UInt8(bytes.count)]) + Data(bytes)
    }

    private static func concat(_ parts: [Data]) -> Data {
        var out = Data()
        for p in parts { out.append(p) }
        return out
    }
}

// MARK: - SAN extractor (subjectAltName → first dNSName)

private struct Reader {
    let bytes: [UInt8]
    var pos: Int
    let end: Int

    init(_ data: Data) {
        self.bytes = Array(data); self.pos = 0; self.end = bytes.count
    }
    init(bytes: [UInt8], start: Int, end: Int) {
        self.bytes = bytes; self.pos = start; self.end = end
    }

    func peek() -> UInt8? { pos < end ? bytes[pos] : nil }

    mutating func readByte() -> UInt8? {
        guard pos < end else { return nil }
        let v = bytes[pos]; pos += 1; return v
    }

    mutating func readLength() -> Int? {
        guard let b0 = readByte() else { return nil }
        if b0 & 0x80 == 0 { return Int(b0) }
        let count = Int(b0 & 0x7F)
        guard count > 0, count <= 4, pos + count <= end else { return nil }
        var len = 0
        for _ in 0..<count {
            guard let b = readByte() else { return nil }
            len = (len << 8) | Int(b)
        }
        return len
    }

    /// Returns TLV header (tag/len/value bounds). Caller must set `pos = valEnd` when done.
    mutating func readTLV() -> (tag: UInt8, len: Int, valStart: Int, valEnd: Int)? {
        guard let tag = readByte(), let len = readLength() else { return nil }
        let vs = pos
        let ve = pos + len
        guard ve <= end else { return nil }
        return (tag, len, vs, ve)
    }

    func slice(_ start: Int, _ end: Int) -> Data {
        let s = max(0, min(start, bytes.count))
        let e = max(0, min(end, bytes.count))
        return s < e ? Data(bytes[s..<e]) : Data()
    }
}

/// Extracts the first SAN dNSName from a cert DER. Falls back to CN via Security if needed.
func hex(_ d: Data) -> String { d.map { String(format: "%02X", $0) }.joined() }


func dnsNameFromCertDER(_ der: Data) -> String? {
    var r = Reader(der)
    guard let certSeq = r.readTLV(), certSeq.tag == 0x30 else {
        return nil
    }

    // tbsCertificate (SEQUENCE)
    var inner = Reader(bytes: r.bytes, start: certSeq.valStart, end: certSeq.valEnd)
    guard let tbs = inner.readTLV(), tbs.tag == 0x30 else {
        return nil
    }

    // Reader limited to TBSCertificate content
    var tbsR = Reader(bytes: inner.bytes, start: tbs.valStart, end: tbs.valEnd)

    // Optional version [0] EXPLICIT (0xA0)
    if let tag = tbsR.peek(), tag == 0xA0 {
        guard let v = tbsR.readTLV() else { return nil }
        tbsR.pos = v.valEnd
    }
    // Skip: serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo (6 TLVs)
    for _ in 0..<6 {
        guard let fld = tbsR.readTLV() else {
            return nil
        }
        tbsR.pos = fld.valEnd
    }

    // Optional issuerUniqueID [1] (0x81) and subjectUniqueID [2] (0x82)
    while let byte = tbsR.peek(), byte == 0x81 || byte == 0x82 {
        guard let uid = tbsR.readTLV() else { return nil }
        tbsR.pos = uid.valEnd
    }

    // Extensions: [3] EXPLICIT (0xA3)
    guard let extTag = tbsR.peek(), extTag == 0xA3 else {
        return nil
    }
    guard let extExplicit = tbsR.readTLV() else {
        return nil
    }

    // Inside [3]: SEQUENCE of Extension
    var extR = Reader(bytes: tbsR.bytes, start: extExplicit.valStart, end: extExplicit.valEnd)
    guard let extSeq = extR.readTLV(), extSeq.tag == 0x30 else {
        return nil
    }

    var listR = Reader(bytes: extR.bytes, start: extSeq.valStart, end: extSeq.valEnd)

    // Walk Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
    while let ext = listR.readTLV() {
        guard ext.tag == 0x30 else {  break }
        var one = Reader(bytes: listR.bytes, start: ext.valStart, end: ext.valEnd)

        guard let oid = one.readTLV(), oid.tag == 0x06 else {
            listR.pos = ext.valEnd; continue
        }
        let oidData = one.slice(oid.valStart, oid.valEnd)

        // IMPORTANT: advance past the OID value before reading next TLV
        one.pos = oid.valEnd

        // 2.5.29.17 = subjectAltName
        let isSAN = (oidData == Data(ASN1.OID.subjectAltName.bytes))

        // optional critical BOOLEAN
        if let t = one.peek(), t == 0x01 {
            if let crit = one.readTLV() {
                one.pos = crit.valEnd
            }
        }

        // extnValue OCTET STRING
        guard let val = one.readTLV(), val.tag == 0x04 else {
            listR.pos = ext.valEnd
            continue
        }

        if isSAN {
            // extnValue contains DER: GeneralNames ::= SEQUENCE OF GeneralName
            var sanR = Reader(bytes: one.bytes, start: val.valStart, end: val.valEnd)
            guard let sanSeq = sanR.readTLV(), sanSeq.tag == 0x30 else {
                return nil
            }

            var gnR = Reader(bytes: sanR.bytes, start: sanSeq.valStart, end: sanSeq.valEnd)
            while let gn = gnR.readTLV() {
                if gn.tag == 0x82 { // [2] dNSName (IA5String)
                    let dnsData = gnR.slice(gn.valStart, gn.valEnd)
                    if let dns = String(data: dnsData, encoding: .ascii) {
                        return dns
                    }
                }
                gnR.pos = gn.valEnd
            }
            return nil
        }

        // next extension
        listR.pos = ext.valEnd
    }
    return nil
}




