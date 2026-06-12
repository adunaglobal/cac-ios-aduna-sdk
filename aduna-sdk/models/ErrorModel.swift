//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  ErrorModel.swift
//  aduna-sdk
//

enum FlowErrorCode: String {
    case user_activity
    case jwt_analysis
    case jwt_iss_validation
    case jwe_creation
    case jwt_creation
    case jwt_decoding
    case generic_failure
}

enum FlowErrorDescription: String {
    case GENERIC_ERROR

    // user_activity errors
    case TIME_OUT
    case USER_CANCELLED
    case CANNOT_REGISTER_TO_CARRIER

    // jwe_creation errors (and jwt decoding errors)
    case FAILED_TO_ENCRYPT_TEMP_TOKEN_JWE
    case PRIVATE_KEY_CREATION_ERROR

    // jwt errors (both creation and decoding)
    case APP_INFO_MANDATORY_DATA_ARE_MISSING
    case CANNOT_SIGN_JWT
    case CERTIFICATE_EXTRACTION_FAILED
    case CERTIFICATE_ISSUER_MISMATCH
    case EMPTY_APP_INFO_AND_HASH
    case ERROR_IN_CERTIFICATE_CHAIN
    case ERROR_ON_DECODING_JWT
    case ERROR_ON_HEADER_CERTIFICATE
    case JWS_PARAMETERS_MISMATCH
    case JWT_CREATION_ERROR
    case JWT_SEGMENTS_COUNT_ERROR
    case INVALID_SIGNATURE
    case KEY_EXTRACTION_ERROR
    case LEAF_CERT_CREATION_ERROR
    case MALFORMED_JWS_FORMAT
    case TIME_VALIDATION_ERROR
    case UNSUPPORTED_ENCRYPTED_RESPONSE_ENC_VALUE
    case UNSUPPORTED_JWT_ALGORITHM
    case UNSUPPORTED_JWT_TYPE
    
    // Errors relevant to invocation URL and JWT payload
    case MISSING_MANDATORY_PARAMETER
    case SCOPE_MISMATCH

}

class ErrorModel: NSObject, Error, LocalizedError {
    let errorCode: FlowErrorCode
    let errorDescriptionText: FlowErrorDescription
    
    init(errorCode: FlowErrorCode, errorDescription: FlowErrorDescription) {
        self.errorCode = errorCode
        self.errorDescriptionText = errorDescription
    }

    var errorDescription: String? {
        return errorDescriptionText.rawValue
    }
}
