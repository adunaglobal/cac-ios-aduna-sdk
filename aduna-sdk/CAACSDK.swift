//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  ENVSDK.swift
//  sdk
//

import CoreTelephony
import Combine
import CryptoKit
internal import JOSESwift
import Network
import SwiftUI

/**
 Contains the function to detect whether an invocation URL corresponds to an ENV operation and holds the data that are required when communicating with SES.
 ```
 CAACSDK.getOperationFromUrl(url: url, cspOptions: cspOptions)
 ```
 */

public class CAACSDK: NSObject {
    
    var useFixedCarrierToken: Bool
    var caacAnalyticsDelegate: CAACAnalyticsDelegate?
    var expInSeconds: Int?
    let constDelayInSec: Double = 0
    
    var uLinkModel:ULinkModel?
    var receivedJwt:ReceivedJwtModel?

    init(useFixedCarrierToken: Bool = false, caacAnalyticsDelegate: CAACAnalyticsDelegate? = nil, expInSeconds: Int? = 120) {
        self.useFixedCarrierToken = useFixedCarrierToken
        self.caacAnalyticsDelegate = caacAnalyticsDelegate
        self.expInSeconds = expInSeconds
    }
    
    /**
     Use this function to get a CAACOperation if the invocation url corresponds to any operation than can be handled by the sdk.
     - Important: The invocation url should be checked in both onOpenURL and  onContinueUserActivity.
     - Parameters:
        - invocationUrl: The url that was used to invoke the App or App Clip.
     - Returns: A ``CAACOperation``, if the url matches an operation that the SDK can handle. `nil`, otherwise.
     */
    public static func getOperationFromUrl(invocationUrl: URL, cspOptions: CAACCSPOptions) -> CAACOperation?{
        if let eNVOptions = cspOptions.eNVCSPOptions,
           let eNVOperation = isValidENV(invocationUrl: invocationUrl,
                                         eNVCSPOptions: eNVOptions,
                                         caacAnalyticsDelegate: cspOptions.caacAnalyticsDelegate
           )
        {
            return  eNVOperation
        } else {
            return nil
        }
    }
    
    static func isValidENV(invocationUrl: URL,
                           eNVCSPOptions: ENVCSPOptions,
                           caacAnalyticsDelegate: CAACAnalyticsDelegate?
    ) -> ENVOperation? {
        let caacSDK = CAACSDK(useFixedCarrierToken: eNVCSPOptions.useFixedCarrierToken, caacAnalyticsDelegate: caacAnalyticsDelegate, expInSeconds: eNVCSPOptions.expInSeconds)
       
        let receivedModel = caacSDK.parseUrl(url: invocationUrl)
        caacSDK.uLinkModel = receivedModel
        if receivedModel != nil {
            return ENVOperation(sdk: caacSDK, eNVCSPOptions: eNVCSPOptions)
        } else {
            return nil
        }
    }

    
    func performNumberVerification() {
        
        guard let payload = uLinkModel?.payload,
              let state = uLinkModel?.state,
              let appName = uLinkModel?.appName
        else {
            caacAnalyticsDelegate?.eventReport(event: .envCspAppError, properties: ["error": FlowErrorDescription.GENERIC_ERROR.rawValue])
            return
        }
        
        getCarrierToken { [self] tokens in
            guard let tokens = tokens, let firstToken = tokens.first
            else {
                SDKLogger.error("No tokens received")
                sendErrorResponseWithAppCallbackUrl(
                    error: ErrorModel(errorCode: .user_activity, errorDescription: .CANNOT_REGISTER_TO_CARRIER),
                    appurl: uLinkModel?.appCallbackUrl
                ) {
                    // Once the URL has been opened (or failed), exit the app:
                    DispatchQueue.main.async {
                        self.exitApp()
                    }
                }
                return
            }

            do {
                
                guard
                    let aggregator1 = payload["credentialId"] as? String,
                    let vctValues = payload["vctValues"] as? [String],
                    let headerTyp = payload["responseJwtType"] as? String
                else {
                    SDKLogger.error("Missing parameter in jwt payload")
                    sendErrorResponseWithAppCallbackUrl(
                        error: ErrorModel(errorCode: .jwt_analysis, errorDescription: FlowErrorDescription.MISSING_MANDATORY_PARAMETER),
                        appurl: uLinkModel?.appCallbackUrl
                    ) {
                        // Once the URL has been opened (or failed), exit the app:
                        DispatchQueue.main.async {
                            self.exitApp()
                        }
                    }
                    return
                }
                
                let jweToken = try encryptTokenFromPayload(payload: payload, tokenToEncrypt: firstToken)
                SDKLogger.debug("Encrypted JWE carrier token: \(jweToken)")
                
                do {
                    let sdkPrivateSecKey = try loadOrCreatePrivateKey()
                    
                    let issuerJwt = try createIssuerJWT(
                        sdkPrivateSecKey: sdkPrivateSecKey,
                        headerTyp: headerTyp,
                        vct: vctValues,
                        expInSeconds: self.expInSeconds ?? 120
                    )
                    SDKLogger.debug("Issuer JWT: \(issuerJwt)")
                    
                    let consentData = payload["consent_data"] as? String ?? ""
                    let nonce = payload["nonce"] as? String ?? ""
                    SDKLogger.debug("Consent data: \(consentData)\nNonce: \(nonce)")

                    let carrierHint = payload["carrierHint"] as? String ?? ""
                    SDKLogger.debug("Carrier hint is:\(carrierHint)")

                    
                    let keyBindingJwt = try createKeyBindingJWT(
                        privateSecKey: sdkPrivateSecKey,
                        appName: appName,
                        state: state,
                        consentData: consentData,
                        nonce: nonce,
                        carrierHint: carrierHint,
                        jweToken: jweToken,
                        issuerJwt: issuerJwt
                    )
                    SDKLogger.debug("Binding JWT: \(keyBindingJwt)")
                    
                    let combinedJwtString = issuerJwt + "~" + keyBindingJwt
                    
                    let vpToken = [aggregator1: [combinedJwtString]]

                    let dataResponse = DataResponse(vp_token: vpToken)
                    let responseModel = ResponseJwtModel(protocol: "openid4vp-v1-unsigned", data: dataResponse)

                    // this is to print responseModel
                    let encoder = JSONEncoder()
                    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

                    if let jsonData = try? encoder.encode(responseModel),
                       let jsonString = String(data: jsonData, encoding: .utf8) {
                        SDKLogger.debug("OpenID4VP Response is \(jsonString)")
                    }
                    // omit if print of responseModel is not needed
                    
                    sendResponseWithAppCallbackUrl(
                        response: responseModel
                    ) {
                        // Once the URL has been opened (or failed), exit the app:
                        DispatchQueue.main.async {
                            self.exitApp()
                        }
                    }
                    
                } catch {
                    SDKLogger.error("Failed to create JWT: \(error.localizedDescription)")
                    sendErrorResponseWithAppCallbackUrl(
                        error: ErrorModel(errorCode: .jwt_creation, errorDescription: FlowErrorDescription(rawValue: error.localizedDescription) ?? .GENERIC_ERROR),
                        appurl: uLinkModel?.appCallbackUrl
                    ) {
                        // Once the URL has been opened (or failed), exit the app:
                        DispatchQueue.main.async {
                            self.exitApp()
                        }
                    }
                    return
                }
        
                
            } catch {
                SDKLogger.error("Encryption failed: \(error.localizedDescription)")
                sendErrorResponseWithAppCallbackUrl(
                    error: ErrorModel(errorCode: .jwe_creation, errorDescription: FlowErrorDescription(rawValue: error.localizedDescription) ?? .GENERIC_ERROR),
                    appurl: uLinkModel?.appCallbackUrl
                ) {
                    // Once the URL has been opened (or failed), exit the app:
                    DispatchQueue.main.async {
                        self.exitApp()
                    }
                }
                return
            }
        }
    }
    
    func sendErrorResponseWithAppCallbackUrl(
        error: ErrorModel,
        appurl: URL?,
        onComplete: @escaping () -> Void
    ) {
        guard let appCallbackUrl = appurl,
              var comps = URLComponents(url: appCallbackUrl, resolvingAgainstBaseURL: false)
        else {
            SDKLogger.error("No appCallbackUrl set")
            caacAnalyticsDelegate?.eventReport(event: .envCspAppError, properties: ["error": FlowErrorDescription.MISSING_MANDATORY_PARAMETER.rawValue])
            onComplete()
            return
        }
                
        var items = comps.queryItems ?? []
        items.append(URLQueryItem(name: "error", value: error.errorCode.rawValue))
        items.append(URLQueryItem(name: "error_description", value: error.errorDescription))
        if (uLinkModel?.aspState != nil) {
            items.append(URLQueryItem(name: "state", value: uLinkModel?.aspState))
        }
        comps.queryItems = items

        guard let finalUrl = comps.url
        else {
            SDKLogger.error("Malformed final URL")
            caacAnalyticsDelegate?.eventReport(event: .envCspAppError, properties: ["error": FlowErrorDescription.GENERIC_ERROR.rawValue])
            onComplete()
            return
        }
        caacAnalyticsDelegate?.eventReport(event: .envOpeningASPCallbackUrlEvent, properties: ["url": appCallbackUrl.absoluteString, "vpopenid4token": false, "error": error.errorCode.rawValue, "error_description": error.errorDescription ?? "GENERIC_ERROR"])
        SDKLogger.debug("Opening Callback URL with error description: \(finalUrl.absoluteString)")

        self.openUrl(finalUrl) {
            onComplete()
        }
    }
    
    func sendResponseWithAppCallbackUrl<T: Encodable>(
        response: T,
        onComplete: @escaping () -> Void
    ) {
        let encoder = JSONEncoder()
        guard
            let jsonData = try? encoder.encode(response),
            let jsonString = String(data: jsonData, encoding: .utf8)
        else {
            SDKLogger.error("Failed to JSON-encode response")
            caacAnalyticsDelegate?.eventReport(event: .envCspAppError, properties: ["error": FlowErrorDescription.GENERIC_ERROR.rawValue])
            onComplete()
            return
        }

        guard let appCallbackUrl = uLinkModel?.appCallbackUrl,
              var comps = URLComponents(url: appCallbackUrl, resolvingAgainstBaseURL: false)
        else {
            SDKLogger.error("No appCallbackUrl set")
            caacAnalyticsDelegate?.eventReport(event: .envCspAppError, properties: ["error": FlowErrorDescription.MISSING_MANDATORY_PARAMETER.rawValue])
            onComplete()
            return
        }
        var items = comps.queryItems ?? []
        items.append(URLQueryItem(name: "openID4VPCSPResponse", value: jsonString))
        if (uLinkModel?.aspState != nil) {
            items.append(URLQueryItem(name: "state", value: uLinkModel?.aspState))
        }
        comps.queryItems = items

        guard let finalUrl = comps.url else {
            SDKLogger.error("Malformed final URL")
            caacAnalyticsDelegate?.eventReport(event: .envCspAppError, properties: ["error": FlowErrorDescription.GENERIC_ERROR.rawValue])
            onComplete()
            return
        }

        caacAnalyticsDelegate?.eventReport(event: .envOpeningASPCallbackUrlEvent, properties: ["url": appCallbackUrl.absoluteString, "vpopenid4token": true])


        SDKLogger.debug("Opening Callback URL: \(finalUrl.absoluteString)")
        self.openUrl(finalUrl) { onComplete() }
    
    }
    
    func exitApp(){
        caacAnalyticsDelegate?.eventReport(event: .envExitingAppEvent, properties: nil)
        exit(0)
    }
    
    func openUrl(_ url: URL, completion: @escaping () -> Void){
        if Thread.isMainThread {
            UIApplication.shared.open(url, options: [:]) { _ in
                completion()
            }
        } else {
            DispatchQueue.main.async {
                UIApplication.shared.open(url, options: [:]) { _ in
                    // hop back to main for the completion too, if it might touch UI
                    DispatchQueue.main.async {
                        completion()
                    }
                }
            }
        }
    }
    
    // Delegate method called when the entitlement server returns a token
    public func subscriberTokenRefreshed(_ subscriber: CTSubscriber) {
        if let refreshedToken = subscriber.carrierToken {
            self.caacAnalyticsDelegate?.eventReport(event: .envCarrierToken, properties: ["Carrier token refreshed:": "true"])
            SDKLogger.debug("Successfully refreshed carrier token: \(refreshedToken.base64EncodedString())")
        }
        else {
            self.caacAnalyticsDelegate?.eventReport(event: .envCarrierToken, properties: ["Carrier token": "not refreshed"])
            SDKLogger.debug("Carrier token not refreshed")
        }
    }
    
    func getCarrierToken (completion: (([String]?) -> Void)?) {
        DispatchQueue.global().asyncAfter(deadline: .now() + constDelayInSec) {
            var tokens: [String]? = []
            if self.useFixedCarrierToken {
                tokens?.append("insert_here_your_testing_carrier_token")
                completion?(tokens)
            }
            else {
                var numOfSim: Int = 0
                CTSubscriberInfo.subscribers().forEach{ sub in
                    if let tokenTmp = sub.carrierToken?.base64EncodedString() {
                        self.caacAnalyticsDelegate?.eventReport(event: .envCarrierToken, properties: ["token":"found"])
                        SDKLogger.debug("A SIM matching your app’s carrier descriptors is present.")
                        numOfSim += 1
                        tokens?.append(tokenTmp)
                        
                    } else {
                        self.caacAnalyticsDelegate?.eventReport(event: .envCarrierToken, properties: ["token":"not found"])
                        SDKLogger.debug("No SIM matching your app’s carrier descriptors is present.")
                        SDKLogger.debug("Requesting new token...")
                        let isTokenRefreshed = sub.refreshCarrierToken()
                        if  isTokenRefreshed,
                            let refreshedToken = sub.carrierToken?.base64EncodedString() {
                                self.caacAnalyticsDelegate?.eventReport(event: .envCarrierToken, properties: ["Carrier token":"refreshed"])
                                numOfSim += 1
                                tokens?.append(refreshedToken)
                        }
                        else {
                            self.caacAnalyticsDelegate?.eventReport(event: .envCarrierToken, properties: ["Carrier token": "not refreshed"])
                        }
                    }
                }

                DispatchQueue.main.async {
                    switch numOfSim {
                    case 0:
                        SDKLogger.error("No valid SIMs were found")
                        completion?(nil)
                    case 1:
                        completion?(tokens)
                    default: // numOfSim > 1 do not suppport Dual SIM mode
                        if let mainToken = tokens?.first {
                            tokens = [mainToken]
                        }
                        else if let secondToken = tokens?.last {
                            tokens = [secondToken]
                        }
                        else {
                            tokens = nil
                        }
                        completion?(tokens)
                    }
                    
                }
            }
        }
    }
    
    // Function to parse url for NV2.0 
    private func parseUrl(url: URL) -> ULinkModel? {
        SDKLogger.debug("This is the invocation url: \(url)")
        let validScopes = ["dpv:FraudPreventionAndDetection#number-verification-verify-read",
                           "dpv:FraudPreventionAndDetection#number-verification:verify",
                           "dpv:FraudPreventionAndDetection#number-verification:device-phone-number:read",
                           "openid dpv:FraudPreventionAndDetection number-verification:device-phone-number:read",
                           "openid dpv:FraudPreventionAndDetection number-verification:verify"]
        
        guard let appInfoJwt = url.valueOf("app_info_jwt"),
              let scope = url.valueOf("scope")
        else {
            let errorDescription = FlowErrorDescription.MISSING_MANDATORY_PARAMETER.rawValue
            caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": "invocation_url_error", "error_description": errorDescription])
            SDKLogger.error("One of the mandatory parameters of invocation URL is missing")
            return nil
        }
        
        if !validScopes.contains(scope) {
            SDKLogger.error("Invocation URL scope is not the expected")
            let errorCode = FlowErrorCode.generic_failure.rawValue
            let errorDescription = FlowErrorDescription.SCOPE_MISMATCH.rawValue
            caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription])
            return nil
        }
        
        if appInfoJwt.isEmpty {
            SDKLogger.error("appInfoJwt is empty")
            let error = FlowErrorCode.jwt_analysis.rawValue
            let errorDescription = FlowErrorDescription.EMPTY_APP_INFO_AND_HASH.rawValue
            caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": error, "error_description": errorDescription])
            return nil
        }
        
        do {
            let (headerAppInfo, payloadAppInfo, signatureAppInfo) = try decodeJWTComponents(appInfoJwt)
            SDKLogger.debug("AppInfo JWT decoded - Header: \(headerAppInfo)")
            SDKLogger.debug("AppInfo JWT decoded - Payload: \(payloadAppInfo)")
            SDKLogger.debug("AppInfo JWT decoded - Signature: \(signatureAppInfo.base64URLEncodedString())")
            
            /* ------------ HEADER ANALYSIS ----------------
            This is to extract leaf, intermediate and root certificate and create an array of SecCertificates
                    - first item = leaf certificate
                    - second item = intermediate certificate
                    - last item = root certificate
            
                    The JWT contains the following headers:
                        - alg; The JWT algorithm. Will be 'ES256'
                        - typ; The type of the JWT. Will be 'oauth-authz-req+jwt'
                        - x5c; The certificate chain of Aduna. The leaf certificate should be used to verify the signing of the JWT.
                               The root certificate should be used to verify the authenticity of the JWT.
            */
            guard let certificatesAppInfo = extractCertificatesFromHeader(header: headerAppInfo)
            else {
                SDKLogger.error("Failed to parse App Info JWT certificate.")
                let errorCode = FlowErrorCode.jwt_analysis.rawValue
                let errorDescription = FlowErrorDescription.ERROR_IN_CERTIFICATE_CHAIN.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription])
                return nil
            }

            for (i, cert) in certificatesAppInfo.enumerated() {
                SDKLogger.debug("x5c[\(i)] subject: \(String(describing: SecCertificateCopySubjectSummary(cert)))")
            }
            
            
            /* This is to verify that the certificate chain is valid:
               Certificates are parsable/usable,
               Verify signatures along the chain,
               Check Validity Period - notBefore/notAfter. */
            if !verifyChain(certificates: certificatesAppInfo) {
                SDKLogger.error("Failed to verify the chain of header certificates in AppInfoJwt.")
                let errorCode = FlowErrorCode.jwt_analysis.rawValue
                let errorDescription = FlowErrorDescription.ERROR_IN_CERTIFICATE_CHAIN.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription])
                return nil
            }
            
            // This is to extract DNS and fingerprint from root certificate in order to check if the issuer is trusted.
            guard let certIdAppInfo = extractCertificateIdentityFromJWTHeader(header: headerAppInfo)
            else {
                SDKLogger.error("Failed to parse appInfo JWT certificate.")
                let errorCode = FlowErrorCode.jwt_analysis.rawValue
                let errorDescription = FlowErrorDescription.ERROR_ON_HEADER_CERTIFICATE.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription])
                return nil
            }
            
            // This is to confirm if the issuer is trusted.
            let areAppInfoClaimsValid = validateClaims(payload: payloadAppInfo, issuer: certIdAppInfo)
            if (!areAppInfoClaimsValid) {
                SDKLogger.error("Claims of the appinfo JWT is not valid")
                let errorCode = FlowErrorCode.jwt_iss_validation.rawValue
                let errorDescription = FlowErrorDescription.CERTIFICATE_ISSUER_MISMATCH.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription])
                return nil
            }
            
            let isPayloadLifetimeValid = validateJwtLifetime(payload: payloadAppInfo)
            if (!isPayloadLifetimeValid) {
                SDKLogger.error("Lifetime of the payload is invalid")
                let errorCode = FlowErrorCode.jwt_analysis.rawValue
                let errorDescription = FlowErrorDescription.TIME_VALIDATION_ERROR.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription])
                return nil
            }
            
            // This is to extract the public key from the leaf certificate.
            guard let leafAppInfo = certificatesAppInfo.first,
                  let publicKeyAppInfo = SecCertificateCopyKey(leafAppInfo)
            else {
                SDKLogger.error("Failed to extract public key in AppInfoJwt.")
                let errorCode = FlowErrorCode.jwt_analysis.rawValue
                let errorDescription = FlowErrorDescription.KEY_EXTRACTION_ERROR.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription])
                return nil
            }
            
            // -------------------SIGNATURE VERIFICATION ----------------------
            // This is to verify the signature of the jwt based on the leaf certificate public key
            let isAppInfoSignatureValid = verifyJWTSignature(jwtString: appInfoJwt, publicKey: publicKeyAppInfo)
            if (!isAppInfoSignatureValid) {
                SDKLogger.error("Signature of the appinfo JWT is not valid")
                let errorCode = FlowErrorCode.jwt_analysis.rawValue
                let errorDescription = FlowErrorDescription.INVALID_SIGNATURE.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription])
                return nil
            }

            guard
                let appCallbackUrlString = payloadAppInfo["appCallbackUrl"] as? String,
                let appCallbackUrl       = URL(string: appCallbackUrlString)
            else {
                SDKLogger.error("Missing or invalid appCallbackUrl in AppCallback JWT")
                let errorCode = FlowErrorCode.jwt_analysis.rawValue
                let errorDescription = FlowErrorDescription.APP_INFO_MANDATORY_DATA_ARE_MISSING.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription])
                return nil
            }
            SDKLogger.debug("appCallbackUrl: \(appCallbackUrl)")
            
            // ---------------------------------------------------------------------------------------------------
            // APP INFO JWT certificates in header are valid, signature is verified and appCallbackUrl can be used onwards to communicate successful and failure cases
            // ---------------------------------------------------------------------------------------------------
            
            /* ------------------- HEADER ANALYSIS ----------------------
                      The JWT header contains the following:
                        - alg; The algorithm to be used for the jwt creation. The supported value is "ES256"
                        - typ; The expected type shall be "oauth-authz-req+jwt" and shall be used for the jwt creation
                        - x5c; An array of certificates (has been verified earlier)
            */
            
            guard let alg = headerAppInfo["alg"] as? String,
                  let typ = headerAppInfo["typ"] as? String
            else {
                SDKLogger.error("Missing alg or typ in jwt header")
                let errorCode = FlowErrorCode.jwt_analysis.rawValue
                let errorDescription = FlowErrorDescription.MISSING_MANDATORY_PARAMETER.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription, "parameter": "in_jwt_header"])
                
                DispatchQueue.main.asyncAfter(deadline: .now() + constDelayInSec) {
                    self.sendErrorResponseWithAppCallbackUrl(
                        error: ErrorModel(errorCode: .jwt_analysis, errorDescription: .MISSING_MANDATORY_PARAMETER),
                        appurl: appCallbackUrl
                    ) {
                        // Once the URL has been opened (or failed), exit the app:
                        DispatchQueue.main.async {
                            self.exitApp()
                        }
                    }
                    
                }
                return ULinkModel(payload: payloadAppInfo, appCallbackUrl: appCallbackUrl, state: "", appName: "appName", aspState: url.valueOf("state"), performNumberVerification: false)
                
            }
            
            guard alg == "ES256"
            else {
                SDKLogger.error("Alg in jwt header is not the expected\nExpected alg=ES256")
                let errorCode = FlowErrorCode.jwt_analysis.rawValue
                let errorDescription = FlowErrorDescription.UNSUPPORTED_JWT_ALGORITHM.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription])
                
                DispatchQueue.main.asyncAfter(deadline: .now() + constDelayInSec) {
                    self.sendErrorResponseWithAppCallbackUrl(
                        error: ErrorModel(errorCode: .jwt_analysis, errorDescription: .UNSUPPORTED_JWT_ALGORITHM),
                        appurl: appCallbackUrl
                    ) {
                        // Once the URL has been opened (or failed), exit the app:
                        DispatchQueue.main.async {
                            self.exitApp()
                        }
                    }
                    
                }
                return ULinkModel(payload: payloadAppInfo, appCallbackUrl: appCallbackUrl, state: "", appName: "appName", aspState: url.valueOf("state"), performNumberVerification: false)
                
            }
            
            guard typ == "oauth-authz-req+jwt"
            else {
                SDKLogger.error("Typ in jwt header is not the expected.\nExpected typ=oauth-authz-req+jwt")
                let errorCode = FlowErrorCode.jwt_analysis.rawValue
                let errorDescription = FlowErrorDescription.UNSUPPORTED_JWT_TYPE.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription])
                
                DispatchQueue.main.asyncAfter(deadline: .now() + constDelayInSec) {
                    self.sendErrorResponseWithAppCallbackUrl(
                        error: ErrorModel(errorCode: .jwt_analysis, errorDescription: .UNSUPPORTED_JWT_TYPE),
                        appurl: appCallbackUrl
                    ) {
                        // Once the URL has been opened (or failed), exit the app:
                        DispatchQueue.main.async {
                            self.exitApp()
                        }
                    }
                    
                }
                return ULinkModel(payload: payloadAppInfo, appCallbackUrl: appCallbackUrl, state: "", appName: "appName", aspState: url.valueOf("state"), performNumberVerification: false)
                
            }

            
            
            /* ------------------- PAYLOAD ANALYSIS ----------------------
                      The JWT contains the following claims:
                        - appName; The name of the application in a readable format
                        - appCallbackUrl; The URL to return the focus to the ASP application from the CSP Application/App Clip
                        - carrierHint; The carrier PLMN ID in the format '&lt;mcc&gt;&lt;mnc&gt;'
                        - clientId; The client ID of the application for the CSP
                        - credentialId; The 'vpRequest.credentialId' value from the request to identify the returned temp-/carrier-token in the response from the CSP Application/App Clip
                        - encryptedResponseEncValuesSupported; The supported encryption algorithm(s) as part of the ECDH-ES algorithm to encrypt the temp-/carrier-token. Is an array of strings. The supported value is 'A128GCM'
                        - exp; The expiry time of this JWT
                        - iat; The creation time of this JWT
                        - iss; The issuer of the JWT indicating Aduna
                        - jwks; The ephemeral public key used with the ECDH-ES algorithm to encrypt the temp-/carrier-token
                        - nonce; The nonce should be copied as is to the response claim
                        - responseJwtType; The 'typ' value of the Issuer JWT (as part of the operator token) in the response from the CSP Application/App Clip. Will be 'dc-authorization+sd-jwt'
                        - scope; The scope(s) of the request
                        - state; The state should be copied as is to the response claim
                        - vctValues; The VCT values to acquire the temp-/carrier-token for
            */
            
            let aggrState = payloadAppInfo["state"] as? String
            SDKLogger.debug("aggregator state is \(aggrState ?? "not found")")

            guard
                var appName = payloadAppInfo["appName"] as? String
            else {
                SDKLogger.error("Missing appName in AppCallback JWT")
                let errorCode = FlowErrorCode.jwt_analysis.rawValue
                let errorDescription = FlowErrorDescription.APP_INFO_MANDATORY_DATA_ARE_MISSING.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription])
                DispatchQueue.main.asyncAfter(deadline: .now() + constDelayInSec) {
                    self.sendErrorResponseWithAppCallbackUrl(
                        error: ErrorModel(errorCode: .jwt_analysis, errorDescription: .APP_INFO_MANDATORY_DATA_ARE_MISSING),
                        appurl: appCallbackUrl
                    ) {
                        // Once the URL has been opened (or failed), exit the app:
                        DispatchQueue.main.async {
                            self.exitApp()
                        }
                    }
                }
                return ULinkModel(payload: nil, appCallbackUrl: appCallbackUrl, state: aggrState ?? "", appName: "", aspState: url.valueOf("state"), performNumberVerification: false)
            }
            //if appName exceeds 30 characters, shorten it to 30
            appName = appName.count > 30 ? String(appName.prefix(30)+"...") : appName
            
            let scopeOfJwt = payloadAppInfo["scope"] as? String
            SDKLogger.debug("Scope of JWT app info is \(String(describing: scopeOfJwt))")
            if (scopeOfJwt != nil && scopeOfJwt != scope) {
                SDKLogger.error("Scope of the invocation URL and scope of the app_info_jwt payload do not match")
                let errorCode = FlowErrorCode.jwt_analysis.rawValue
                let errorDescription = FlowErrorDescription.SCOPE_MISMATCH.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription])
                
                DispatchQueue.main.asyncAfter(deadline: .now() + constDelayInSec) {
                    self.sendErrorResponseWithAppCallbackUrl(
                        error: ErrorModel(errorCode: .jwt_analysis, errorDescription: .SCOPE_MISMATCH),
                        appurl: appCallbackUrl
                    ) {
                        // Once the URL has been opened (or failed), exit the app:
                        DispatchQueue.main.async {
                            self.exitApp()
                        }
                    }
                }
                return ULinkModel(payload: nil, appCallbackUrl: appCallbackUrl, state: aggrState ?? "", appName: appName, aspState: url.valueOf("state"), performNumberVerification: false)
            }
    
            guard
                let encArray = payloadAppInfo["encryptedResponseEncValuesSupported"] as? [String]
            else {
                SDKLogger.error("encryptedResponseEncValuesSupported not found")
                let errorCode = FlowErrorCode.jwt_analysis.rawValue
                let errorDescription = FlowErrorDescription.MISSING_MANDATORY_PARAMETER.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription, "parameter": "encryptedResponseEncValuesSupported"])
                
                DispatchQueue.main.asyncAfter(deadline: .now() + constDelayInSec) {
                    self.sendErrorResponseWithAppCallbackUrl(
                        error: ErrorModel(errorCode: .jwt_analysis, errorDescription: .MISSING_MANDATORY_PARAMETER),
                        appurl: appCallbackUrl
                    ) {
                        // Once the URL has been opened (or failed), exit the app:
                        DispatchQueue.main.async {
                            self.exitApp()
                        }
                    }
                }
                return ULinkModel(payload: payloadAppInfo, appCallbackUrl: appCallbackUrl, state: aggrState ?? "", appName: appName, aspState: url.valueOf("state"), performNumberVerification: false)
            }
            
            let encStr = encArray.joined(separator: ",")
            SDKLogger.debug("encrypted response is \(encStr)")
            guard encArray.contains("A128GCM") else {
                SDKLogger.error("Not supported encryptedResponseEncValuesSupported")
                let errorCode = FlowErrorCode.jwt_analysis.rawValue
                let errorDescription = FlowErrorDescription.UNSUPPORTED_ENCRYPTED_RESPONSE_ENC_VALUE.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription])
                
                DispatchQueue.main.asyncAfter(deadline: .now() + constDelayInSec) {
                    self.sendErrorResponseWithAppCallbackUrl(
                        error: ErrorModel(errorCode: .jwt_analysis, errorDescription: .UNSUPPORTED_ENCRYPTED_RESPONSE_ENC_VALUE),
                        appurl: appCallbackUrl
                    ) {
                        // Once the URL has been opened (or failed), exit the app:
                        DispatchQueue.main.async {
                            self.exitApp()
                        }
                    }
                }
                return ULinkModel(payload: payloadAppInfo, appCallbackUrl: appCallbackUrl, state: aggrState ?? "", appName: appName, aspState: url.valueOf("state"), performNumberVerification: false)
            }
            
            guard
                let _ = payloadAppInfo["credentialId"] as? String,
                let _ = payloadAppInfo["nonce"] as? String,
                let _ = payloadAppInfo["vctValues"] as? [String],
                let _ = payloadAppInfo["responseJwtType"] as? String,
                let jwks = payloadAppInfo["jwks"] as? [String: Any]
            else {
                SDKLogger.error("Missing parameter in jwt payload")
                let errorCode = FlowErrorCode.jwt_analysis.rawValue
                let errorDescription = FlowErrorDescription.MISSING_MANDATORY_PARAMETER.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription, "parameter": "in_jwt_payload"])
                
                DispatchQueue.main.asyncAfter(deadline: .now() + constDelayInSec) {
                    self.sendErrorResponseWithAppCallbackUrl(
                        error: ErrorModel(errorCode: .jwt_analysis, errorDescription: .MISSING_MANDATORY_PARAMETER),
                        appurl: appCallbackUrl
                    ) {
                        // Once the URL has been opened (or failed), exit the app:
                        DispatchQueue.main.async {
                            self.exitApp()
                        }
                    }
                }
                return ULinkModel(payload: payloadAppInfo, appCallbackUrl: appCallbackUrl, state: aggrState ?? "", appName: appName, aspState: url.valueOf("state"), performNumberVerification: false)
            
            }
            
            guard
                let keys = jwks["keys"] as? [[String: Any]],
                let keyData = keys.first,
                let _ = keyData["kty"] as? String,
                let _ = keyData["crv"] as? String,
                let _ = keyData["x"] as? String,
                let _ = keyData["y"] as? String,
                let _ = keyData["use"] as? String,
                let _ = keyData["kid"] as? String,
                let _ = keyData["alg"] as? String
            else {
                SDKLogger.error("Error in JWS")
                let errorCode = FlowErrorCode.jwt_analysis.rawValue
                let errorDescription = FlowErrorDescription.MALFORMED_JWS_FORMAT.rawValue
                caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription])
                
                DispatchQueue.main.asyncAfter(deadline: .now() + constDelayInSec) {
                    self.sendErrorResponseWithAppCallbackUrl(
                        error: ErrorModel(errorCode: .jwt_analysis, errorDescription: .MALFORMED_JWS_FORMAT),
                        appurl: appCallbackUrl
                    ) {
                        // Once the URL has been opened (or failed), exit the app:
                        DispatchQueue.main.async {
                            self.exitApp()
                        }
                    }
                }
                return ULinkModel(payload: payloadAppInfo, appCallbackUrl: appCallbackUrl, state: aggrState ?? "", appName: appName, aspState: url.valueOf("state"), performNumberVerification: false)
            }

       
            SDKLogger.debug("Everything is valid")
            caacAnalyticsDelegate?.eventReport(event: .envParsingInvocationUrlSuccess, properties: nil)
            
            return ULinkModel(payload: payloadAppInfo, appCallbackUrl: appCallbackUrl, state: aggrState ?? "", appName: appName, aspState: url.valueOf("state"), performNumberVerification: true)
                
           
        } catch {
            SDKLogger.error("Failed to decode the app Info JWT: \(error.localizedDescription)")
            let errorCode = FlowErrorCode.jwt_decoding.rawValue
            let errorDescription = error.localizedDescription
            caacAnalyticsDelegate?.eventReport(event: .envInvocationUrlError, properties: ["error": errorCode, "error_description": errorDescription])
            return nil
        }

       
    }
    
    final class NetworkStatus {
        static let shared = NetworkStatus()

        private let monitor = NWPathMonitor()
        private let queue = DispatchQueue(label: "NetworkStatus.Monitor")

        private init() {
            // Start monitoring immediately so currentPath is populated.
            monitor.start(queue: queue)
        }

        var isReachable: Bool { monitor.currentPath.status == .satisfied }
        var isExpensive: Bool { monitor.currentPath.isExpensive }
        var usesWiFi: Bool { monitor.currentPath.usesInterfaceType(.wifi) }
        var usesCellular: Bool { monitor.currentPath.usesInterfaceType(.cellular) }
    }

    func isNetworkReachable() -> Bool {
        NetworkStatus.shared.isReachable
    }
        
}

extension String {
    func containsOnlyDigits() -> Bool {
        let digitRegex = "^[0-9]+$"
        return self.range(of:digitRegex, options: .regularExpression) != nil
    }
}

extension CAACSDK :ObservableObject {}

fileprivate extension URL {
    func valueOf(_ queryParameterName: String) -> String? {
        guard let url = URLComponents(string: self.absoluteString) else { return nil }
        return url.queryItems?.first(where: { $0.name == queryParameterName })?.value
    }
}

