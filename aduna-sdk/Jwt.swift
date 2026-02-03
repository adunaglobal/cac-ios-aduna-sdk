//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  Jwt.swift
//  aduna-sdk
//
//  Created by Dimitrios Kotronis on 21/1/26.
//
internal import JOSESwift
import CryptoKit

func decodeJWTComponents(_ jwt: String) throws -> (header: [String: Any], payload: [String: Any], signature: Data) {
    let segments = jwt.components(separatedBy: ".")
    guard segments.count == 3
    else {
        SDKLogger.error("JWT does not have three parts")
        throw ErrorModel(errorCode: .jwt_decoding, errorDescription: .JWT_SEGMENTS_COUNT_ERROR)
    }

    func decodeBase64URL(_ value: String) -> Data? {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padLength = 4 - base64.count % 4
        if padLength < 4 { base64 += String(repeating: "=", count: padLength) }
        return Data(base64Encoded: base64)
    }

    guard
        let headerData = decodeBase64URL(segments[0]),
        let payloadData = decodeBase64URL(segments[1]),
        let signatureData = decodeBase64URL(segments[2]),
        let headerJson = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
        let payloadJson = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any]
    else {
        SDKLogger.error("Error at decoding JWT to JSON")
        throw ErrorModel(errorCode: .jwt_decoding, errorDescription: .ERROR_ON_DECODING_JWT)
    }

    return (headerJson, payloadJson, signatureData)
}

func extractCertificatesFromHeader(header: [String: Any]) -> [SecCertificate]? {
    guard let x5cArray = header["x5c"] as? [String],
          !x5cArray.isEmpty
    else {
        return nil
    }

    var certificates: [SecCertificate] = []

    for certBase64 in x5cArray {
        guard let certData = Data(base64Encoded: certBase64),
              let cert = SecCertificateCreateWithData(nil, certData as CFData)
        else {
            return nil
        }
        certificates.append(cert)
    }

    return certificates
}

func verifyChain(certificates: [SecCertificate]) -> Bool {
    guard !certificates.isEmpty else {
        SDKLogger.error("verifyChain: No certificates provided")
        return false
    }

    SDKLogger.debug("verifyChain: Received \(certificates.count) certificate(s)")

    let policy = SecPolicyCreateBasicX509()
    var trust: SecTrust?

    let status = SecTrustCreateWithCertificates(certificates as CFArray,
                                                    policy,
                                                    &trust)
    guard status == errSecSuccess, let secTrust = trust else {
        SDKLogger.error("verifyChain: SecTrustCreateWithCertificates failed: \(status)")
        return false
    }

    if let root = certificates.last {
        SecTrustSetAnchorCertificates(secTrust, [root] as CFArray)
        SecTrustSetAnchorCertificatesOnly(secTrust, true)
    }

    var error: CFError?
    let ok = SecTrustEvaluateWithError(secTrust, &error)
    if ok {
        SDKLogger.debug("verifyChain: Trust evaluation succeeded.")
        return true
    }

    if let err = error {
        SDKLogger.error("verifyChain: Trust evaluation failed with CFError:")
        SDKLogger.error("Error: \(err)")
        SDKLogger.error("Code: \(CFErrorGetCode(err))")
        if let domain = CFErrorGetDomain(err) as String? {
            SDKLogger.error("Domain: \(domain)")
        }
        if let userInfo = CFErrorCopyUserInfo(err) as? [String: Any] {
            SDKLogger.error("UserInfo:")
            for (key, value) in userInfo {
                SDKLogger.error("       - \(key): \(value)")
            }
        }
    } else {
        SDKLogger.error("verifyChain: Trust evaluation failed with no error object.")
    }
    return false
}

func extractCertificateIdentityFromJWTHeader(header: [String: Any]) -> CertIdentity? {
    
    guard let x5cArray = header["x5c"] as? [String],
          let certBase64 = x5cArray.last,     // last in the array is the root certificate
          let certData = Data(base64Encoded: certBase64, options: [.ignoreUnknownCharacters]),
          let dns = dnsNameFromCertDER(certData)
    else {
        return nil
    }

    SDKLogger.debug("DNS name is: \(dns)")

    // Compute SHA-256 fingerprint over full DER
    let digest = SHA256.hash(data: certData)
    let hex = digest.map { String(format: "%02X", $0) }.joined()

    // CertIdentity initializer will canonicalize to colon-separated uppercase
    return CertIdentity(dns: dns, sha256Fingerprint: hex)
}

func validateJwtLifetime(payload: [String: Any]) -> Bool {
    
    guard let exp = payload["exp"] as? TimeInterval,
          let _ = payload["iat"] as? TimeInterval
    else {
        SDKLogger.error("Missing mandatory parameter iat/exp in payload")
        return false
    }
    
    let expirationDate = Date(timeIntervalSince1970: exp)
    if expirationDate < Date() {
        SDKLogger.error("Token expired at \(expirationDate)")
        return false
    }
    else {
        SDKLogger.debug("Token will expire at \(expirationDate)")
        return true
    }
}

func validateClaims(payload: [String: Any], issuer: CertIdentity) -> Bool {
    let trustedIssuers: Set<CertIdentity> = [
        CertIdentity(dns: "dev.aggregator.com", sha256Fingerprint: "1E:A9:4E:85:CD:B8:04:0F:B9:EF:66:83:39:23:4A:A6:44:18:AB:30:CA:A7:48:36:4C:67:55:9E:17:6B:E4:B0"),
        CertIdentity(dns:"gnp.adunaglobal.net", sha256Fingerprint: "DA:04:FC:63:10:53:79:BE:87:D3:48:E0:D4:DF:B2:14:18:A9:BE:9D:B7:F4:7C:86:DE:37:F6:0D:0B:03:E4:11")

    ]

    guard trustedIssuers.contains(issuer)
    else {
        SDKLogger.error("Not trusted issuer: \(issuer)")
        return false
    }
    SDKLogger.debug("Issuer \(issuer) is trusted")
    
    guard let payloadIssuer = payload["iss"] as? String,
              payloadIssuer == issuer.dns
    else {
        SDKLogger.error("Payload issuer: \(payload["iss"] ?? "nil") != x5c Issuer: \(issuer.dns)")
        return false
    }
    return true
    
}

func verifyJWTSignature(jwtString: String, publicKey: SecKey) -> Bool {
    do {
        let jwsFromJwt = try JWS(compactSerialization: jwtString)
        
        guard let alg = jwsFromJwt.header.algorithm
        else {
            SDKLogger.error("Missing algorithm in JWT header.")
            return false
        }
        
        let verifier: JOSESwift.Verifier?
        switch alg {
           case .ES256:
            verifier = Verifier(signatureAlgorithm: .ES256, key: publicKey)
           default:
            SDKLogger.error("Unsupported algorithm in JWT header: \(jwsFromJwt.header.algorithm?.rawValue ?? "nil")")
            return false
        }
        
        guard let validVerifier = verifier else {
            SDKLogger.error("Failed to create verifier.")
            return false
        }
        
        // Validate the JWS using the verifier
        let isSignatureValid = jwsFromJwt.isValid(for: validVerifier)
        return isSignatureValid
        
    } catch let error as JOSESwiftError {
        switch error {
        case .signingFailed(let description):
            SDKLogger.error("Signing failed: \(description)")
        case .verifyingFailed(let description):
            SDKLogger.error("Verification failed: \(description)")
        case .componentNotValidBase64URL(let component):
            SDKLogger.error("Invalid base64url encoding in component: \(component)")
        case .componentCouldNotBeInitializedFromData(let data):
            SDKLogger.error("Could not initialize component from data: \(data.base64EncodedString())")
        case .wrongDataEncoding(let data):
            SDKLogger.error("Wrong data encoding: \(data.base64EncodedString())")
        case .localAuthenticationFailed(let errorCode):
            SDKLogger.error("Local authentication failed with code: \(errorCode)")
        default:
            // For all other enum cases
            SDKLogger.error("JOSESwiftError: \(error.localizedDescription)")
        }
        return false
    } catch {
        SDKLogger.error("Unexpected error during JWT verification: \(error.localizedDescription)")
        return false
    }
}
    
func encryptTokenFromPayload(payload: [String: Any], tokenToEncrypt: String) throws -> String {
    
    // Extract JWK fields from payload
    guard
        let jwks = payload["jwks"] as? [String: Any],
        let keys = jwks["keys"] as? [[String: Any]],
        let keyData = keys.first,
        let kty = keyData["kty"] as? String,
        let crv = keyData["crv"] as? String,
        let xStr = keyData["x"] as? String,
        let yStr = keyData["y"] as? String,
        let use = keyData["use"] as? String,
        let _ = keyData["kid"] as? String,
        let _ = keyData["alg"] as? String
    else {
        throw ErrorModel(
            errorCode: .jwt_analysis,
            errorDescription: .MALFORMED_JWS_FORMAT
        )
    }
    
    guard crv == "P-256",
          kty == "EC",
          use == "enc"
    else {
        throw ErrorModel(
            errorCode: .jwe_creation,
            errorDescription: .JWS_PARAMETERS_MISMATCH
        )
    }
    
    // Construct EC public key JWK
    let jwk = ECPublicKey(crv: .P256, x: xStr, y: yStr)

    // Extract encryption algorithm and content encryption method
    guard
        let algStr = keyData["alg"] as? String,
        let encArray = payload["encryptedResponseEncValuesSupported"] as? [String],
        encArray.contains("A128GCM"),
        let alg = KeyManagementAlgorithm(rawValue: algStr),
        let enc = ContentEncryptionAlgorithm(rawValue: "A128GCM")
    else {
        throw ErrorModel(
            errorCode: .jwt_analysis,
            errorDescription: .UNSUPPORTED_JWT_ALGORITHM
        )
    }

    SDKLogger.debug("algStr from payload: \(algStr)")
    SDKLogger.debug("encStr from payload: A128GCM")
    SDKLogger.debug("Parsed alg: \(alg)")
    SDKLogger.debug("Parsed enc: \(enc)")
   
    
    // Create Encrypter
    guard let encrypter = Encrypter(
        keyManagementAlgorithm: alg,
        contentEncryptionAlgorithm: enc,
        encryptionKey: jwk
    ) else {
        throw ErrorModel(
            errorCode: .jwt_analysis,
            errorDescription: .UNSUPPORTED_ENCRYPTED_RESPONSE_ENC_VALUE
        )
    }

    // Encrypt token
    let safeTokenToEncrypt = tokenToEncrypt.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
    let token = TokenPayload(temp_token: safeTokenToEncrypt)
    do {
        let encoder = JSONEncoder()
        let tokenData = try encoder.encode(token)
        if let tokenJsonString = String(data: tokenData, encoding: .utf8) {
            SDKLogger.debug("Token as JSON string: \(tokenJsonString)")
        }
        
        // Create payload
        let payload = Payload(tokenData)
        // Create header
        let header = try JWEHeader(parameters: [
            "alg": "ECDH-ES",
            "enc": "A128GCM",
            "kid": "1",
            "typ": "JWT"
        ])
        
        let jwe = try JWE(header: header, payload: payload, encrypter: encrypter)

        return jwe.compactSerializedString
        
    } catch {
        SDKLogger.error("Could not encode the carrier token as json: \(error.localizedDescription)")
        throw ErrorModel(
            errorCode: .jwe_creation,
            errorDescription: .FAILED_TO_ENCRYPT_TEMP_TOKEN_JWE
        )
    }
}

func createSelfSignedLeafBase64(
    using sdkPrivateSecKey: SecKey,
    subjectCN: String = "AdunaGlobalSdk",
    org: String = "AdunaGlobal",
    country: String = "GR",
    validFor seconds: Int = 270
) throws -> String {

    do {
        // Create the issuer key as an X509 private key
        let issuerKey = try Certificate.PrivateKey(sdkPrivateSecKey)
        // Create the matching public key for the certificate
        let pubSecKey = SecKeyCopyPublicKey(sdkPrivateSecKey)!
        var cfErr: Unmanaged<CFError>?
        guard let x963 = SecKeyCopyExternalRepresentation(pubSecKey, &cfErr) as Data? else {
            throw ErrorModel(errorCode: .jwt_creation, errorDescription: .LEAF_CERT_CREATION_ERROR)
        }
        let cryptoPub = try P256.Signing.PublicKey(x963Representation: x963)
        let publicKey  = Certificate.PublicKey(cryptoPub)
        
        // Subject self-signed
        let dn = DistinguishedName {
            CommonName(subjectCN)
            OrganizationName(org)
            CountryName(country)
        }
        
        // Validity in time
        let now = Date()
        let notBefore = now.addingTimeInterval(-30)
        let notAfter  = now.addingTimeInterval(Double(seconds))
        
        
        // Extensions: leaf certificate to digitally sign a JWT
        let exts = CertificateExtensions {
            Critical(BasicConstraints(notCertificateAuthority: true))
            Critical(KeyUsage(digitalSignature: true))
        }
        
        // Create certificate and sign
        let cert = Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),  //random number
            publicKey: publicKey,
            notValidBefore: notBefore,
            notValidAfter: notAfter,
            issuer: dn,
            subject: dn,
            extensions: exts,
            issuerPrivateKey: issuerKey
        )
        
        // serialize the certificate
        let der = try cert.serializeAsDER()
        return der.base64EncodedString()
    }
    catch {
        SDKLogger.error("Failed to create self signed leaf certificate")
        throw ErrorModel(
            errorCode: .jwt_creation,
            errorDescription: .LEAF_CERT_CREATION_ERROR
        )
    }
}

func XYFromPublicKey(_ publicKey: SecKey) throws -> (x: String, y: String) {
    let raw = try rawPublicKeyBytes(from: publicKey)
    guard raw.first == 0x04 else {
        throw NSError(domain: "JWK", code: 1, userInfo: [NSLocalizedDescriptionKey: "Unexpected key format"])
    }
    // first byte is 0x04; next 32 are X, next 32 are Y
    let coordLength = (raw.count - 1) / 2
    let xData = raw.subdata(in: 1 ..< 1 + coordLength)
    let yData = raw.subdata(in: 1 + coordLength ..< raw.count)

    return (base64URLEncode(xData), base64URLEncode(yData))
}

func rawPublicKeyBytes(from secKey: SecKey) throws -> Data {
    var error: Unmanaged<CFError>?
    guard let data = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
        throw error!.takeRetainedValue() as Error
    }
    return data
}

func base64URLEncode(_ data: Data) -> String {
    let b64 = data.base64EncodedString()
    // remove padding, convert +/→-_,_
    return b64
        .trimmingCharacters(in: ["="])
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
}

func createIssuerJWT(
    sdkPrivateSecKey: SecKey,
    headerTyp: String,
    vct: [String],
    expInSeconds: Int
) throws -> String {
    
    do {
        guard let sdkPublicSecKey = SecKeyCopyPublicKey(sdkPrivateSecKey)  // extract the public key
        else {
            throw ErrorModel(
                errorCode: .jwt_creation,
                errorDescription: .KEY_EXTRACTION_ERROR
            )
        }
        
        let x5c = try createSelfSignedLeafBase64(using: sdkPrivateSecKey)
        SDKLogger.debug("X5C created: \(x5c)")
        let (x, y) = try XYFromPublicKey(sdkPublicSecKey)  // Based on public key, create X and Y for the EC(Elliptic Curve)
        SDKLogger.debug("JWK x: \(x)\nJWK y: \(y)")
        let cnf = JWKRepresentation(alg:"ES256", kty:"EC",crv:"P-256",x:x,y:y, use:"sig")
        
        // Header
        var header = JWSHeader(algorithm: .ES256)
        header.typ = headerTyp
        header.x5c = [x5c]
        
        // Payload
        let now = Int(Date().timeIntervalSince1970)
        
        let claims = JWTIssuerPayload(
            iss: "AdunaGlobalSdk",
            vct: vct,
            cnf: DeviceConfirmation(jwk: cnf),
            exp: now + expInSeconds,
            iat: now
        )
        let payload = try Payload(JSONEncoder().encode(claims))
        
        
        guard let signer = Signer(signatureAlgorithm: .ES256, key: sdkPrivateSecKey)
        else {
            throw ErrorModel(
                errorCode: .jwt_creation,
                errorDescription: .CANNOT_SIGN_JWT
            )
        }
        
        // Create JWS and serialize
        let jws = try JWS(header: header, payload: payload, signer: signer)
        return jws.compactSerializedString
    }
    catch {
        SDKLogger.error("Failed to create issuer JWT: \(error.localizedDescription)")
        throw ErrorModel(
            errorCode: .jwt_creation,
            errorDescription: .JWT_CREATION_ERROR
        )
    }
}

func createKeyBindingJWT(
    privateSecKey: SecKey,
    appName: String,
    state: String,
    consentData: String,
    nonce: String,
    carrierHint: String,
    jweToken: String,
    issuerJwt: String
) throws -> String {
    do {
        // Header
        var header = JWSHeader(algorithm: .ES256)
        header.typ = "kb+jwt"
        
        // Payload
        let consentDataHash = sha256Base64(consentData)
        let sdHash = sha256Base64(issuerJwt + "~")
        
        SDKLogger.debug("Consent data hash: \(consentDataHash)\nSD Hash: \(sdHash)")
        
        let trimmedState = state.trimmingCharacters(in: .whitespacesAndNewlines)
        let jwtPayload = JWTKeyBindingPayload(
            iat: Int(Date().timeIntervalSince1970),      //now timestamp
            aud: appName,
            nonce: nonce,
            encrypted_credential: jweToken,
            consent_data_hash: consentDataHash,
            state: trimmedState.isEmpty ? nil : trimmedState,   // <-- omit if state is empty
            sd_hash: sdHash,
            carrier_hint: carrierHint
        )
        let payload = try Payload(JSONEncoder().encode(jwtPayload))
        
        // Signature
        guard let signer = Signer(signatureAlgorithm: .ES256, key: privateSecKey)
        else {
            throw ErrorModel(
                errorCode: .jwt_creation,
                errorDescription: .CANNOT_SIGN_JWT
            )
        }
        
        // Create JWS and serialize
        let jws = try JWS(header: header, payload: payload, signer: signer)
        return jws.compactSerializedString
    }
    catch {
        SDKLogger.error("Failed to create key binding JWT: \(error)")
        throw ErrorModel(
            errorCode: .jwt_creation,
            errorDescription: .JWT_CREATION_ERROR
        )
    }
}

func sha256Base64(_ input: String) -> String {
    let inputData = Data(input.utf8)
    let digest = SHA256.hash(data: inputData)
    let hashData = Data(digest)
    return hashData.base64EncodedString()
}
