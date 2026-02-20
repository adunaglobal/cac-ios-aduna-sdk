//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//
//  PrivateKey.swift
//  aduna-sdk
//

func loadOrCreatePrivateKey(requireUserPresence: Bool = false) throws -> SecKey {
    enum SDKKeyIds {
        static let tag = "com.adunaglobal.caac.ios.csp.sdk.es256.signingkey"
    }
    
    let tagData = Data(SDKKeyIds.tag.utf8)
    
    let loadQuery: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        kSecAttrApplicationTag as String: tagData,
        kSecReturnRef as String: true
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(loadQuery as CFDictionary, &item)
    if status == errSecSuccess,
       let cf = item,
       CFGetTypeID(cf) == SecKeyGetTypeID() {
        return (cf as! SecKey)
    }

    // Build Access Control (ThisDeviceOnly; privateKeyUsage; optional user presence/biometry gate)
    let flags: SecAccessControlCreateFlags = requireUserPresence ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
    let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        flags,
        nil
    )!


    // Base attributes
    var attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrAccessControl as String: access
        ]
    ]

    #if !targetEnvironment(simulator)
    attrs[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
    #endif

    var error: Unmanaged<CFError>?
    if let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) {
        return key
    }

    // If Secure Enclave creation failed (older device), fall back to software Keychain
    #if !targetEnvironment(simulator)
    // Remove token id and try again
    attrs.removeValue(forKey: kSecAttrTokenID as String)
    error = nil
    if let softKey = SecKeyCreateRandomKey(attrs as CFDictionary, &error) {
        return softKey
    }
    #endif

    SDKLogger.error("Failed to create private key")
    throw ErrorModel(
        errorCode: .jwt_creation,
        errorDescription: .PRIVATE_KEY_CREATION_ERROR
    )
}
