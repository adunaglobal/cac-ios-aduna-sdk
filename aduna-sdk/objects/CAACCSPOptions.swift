//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  CAACOptions.swift
//  aduna-sdk
//

import Foundation
/**
 This class contains the CSP information that CAAC need to operate. To build the instance use the ``Builder``.
 */
public class CAACCSPOptions{
    
    /**
     Use this builder to construct a CAACCSPOptions instance by using ``addENVOptions(useFixedCarrierToken:skipConsentScreen:envAppearance:expInSeconds:)`` and then ``build()``.
     You can optionally add ``addAnalyticsDelegate(caacAnalyticsDelegate:)`` to add a delegate for analytics.
    */
    public class Builder {
        
        private let caacOptions = CAACCSPOptions()
        
        public init(){}
        
        /**
         - Parameters:
            - useFixedCarrierToken: When true, the SDK uses a fixed Carrier Token. It's recomended to set this to ``true`` when the integration with the Carrier network is not yet complete. Set to ``false`` in  production or  real network cases
            - skipConsentScreen: If true consent screen is displayed, otherwise proceed directly to the loading screen.
            - envAppearance: set the ``ENVAppearance`` object that custiomizes the UI.
            - expInSeconds: Expiry in seconds of the NV2 information.
            - rCTThreshold: Refresh Carrier Token Threshold - After the threshold, carrier token has to be refreshed.
         */
        public func addENVOptions(
            useFixedCarrierToken:Bool,
            skipConsentScreen:Bool,
            envAppearance: ENVAppearance,
            expInSeconds: Int,
            rCTThreshold: Double
        ) -> Builder {
            caacOptions.eNVCSPOptions = ENVCSPOptions(useFixedCarrierToken: useFixedCarrierToken,
                                                      skipConsentScreen: skipConsentScreen,
                                                      envAppearance: envAppearance,
                                                      expInSeconds: expInSeconds,
                                                      rCTThreshold: rCTThreshold
            )
            return self
        }
        
        /**
         Optionally add a delegate that implemets ``CAACAnalyticsDelegate`` protocol for analytics.
         */
        public func addAnalyticsDelegate(caacAnalyticsDelegate: CAACAnalyticsDelegate? = nil) -> Builder{
            caacOptions.caacAnalyticsDelegate = caacAnalyticsDelegate
            return self
        }
        
        public func build() -> CAACCSPOptions {
            return caacOptions
        }
    }
    
    var eNVCSPOptions: ENVCSPOptions? = nil
    var caacAnalyticsDelegate: CAACAnalyticsDelegate? = nil
    
}
