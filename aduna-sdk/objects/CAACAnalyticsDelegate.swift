//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  ENVAnalyticsCallbacks.swift
//  sdk
//

import Foundation

public enum CAACAnalyticsEvent: String {
    // This event is accompanied `statusCode` property.
    // - Has `statusCode` property with `Int` value.
    /// Consent Screen appears.
    case envConsentScreen = "ENV_Consent_Screen"
    /// Progress Screen appears.
    case envProgressScreen = "ENV_Progress_Screen"
// Progress Screen appears
//    case envErrorScreen = "ENV_Error_Screen"
    /// User tapped the Consent button at the consent screen.
    case envConsentButton = "ENV_Consent_Button"
    /// User tapped the reject button at the consent screen.
    case envConsentDeclineButton = "ENV_Consent_Decline_Button"
    /// User confirms to decline consent.
    case envConsentDeclinePositiveButton = "ENV_Consent_Decline_Dialog_Positive_Button" // User declines consent
    /// User selects to resume to consent screen after cancelation.
    case envConsentDeclineNegativeButton = "ENV_Consent_Decline_Dialog_Negative_Button" // User resumes consent screen
    /// User taps the cancel button at progress screen.
    case envVerificationProgressCancelledButton = "ENV_Verification_Progress_Cancel_Button"
    /// User confirms to cancel the operation .
    case envVerificationProgressCancellationPositiveButton = "ENV_Verification_Progress_Cancel_Dialog_Positive_Button" // User cancels progress
    /// User declines to operation cancellation.
    case envVerificationProgressCancellationNegativeButton = "ENV_Verification_Progress_Cancel_Dialog_Negative_Button" // User resumes progress
    /// Control returns to ASP through callback URL.
    case envOpeningASPCallbackUrlEvent = "ENV_Open_ASP_Event"
    /// Exiting CSP App.
    case envExitingAppEvent = "ENV_Exit_App_Event"
    /// Consent timeout due to user inactivity.
    case envConsentTimedOutEvent = "ENV_Timeout_Event"
    /// Invocation URL was parsed successfully.
    case envParsingInvocationUrlSuccess = "ENV_Parsing_Invocation_Url_Success"
    /// Invocation URL parsing failed.
    case envInvocationUrlError = "ENV_Invocation_Url_Error"
    /// ENV operation failed.
    case envCspAppError = "ENV_Csp_App_Error"
    /// Events relevant to Carrier Token
    case envCarrierToken = "ENV_Carrier_Token_Event"

}


public protocol CAACAnalyticsDelegate {
    
    func eventReport(event: CAACAnalyticsEvent, properties: [String: Any]?)
    
    

}

struct ConsentReceivedAnalyticsEventData{
    
    let scope: String
    let purpose: String
    let checked: Bool
}
