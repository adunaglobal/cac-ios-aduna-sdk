//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  ContentView.swift
//  sdk
//

import SwiftUI
import OSLog

@available(iOS 18.0, *)
struct ENVContentView: View {
    
    @EnvironmentObject private var eNVsdk: CAACSDK
    @EnvironmentObject private var appearance: ENVAppearance

    @State private var showingAlert: Bool = false
    @State private var timerExpired: Bool = false
    @State private var isLoading: Bool = true
    @State private var isSuccessful: Bool = false

    
    var body: some View {
        let proceedWithENV: Bool = ((eNVsdk.uLinkModel?.performNumberVerification) == true)
        ZStack() {
            VStack {
                if appearance.text.textContentAboveProgress {
                    Text(timerExpired ? "Verifying your phone number. Please wait..." : "Verifying your phone number...")
                        .multilineTextAlignment(appearance.text.alignment == .center ? .center : .leading )
                        .padding(.bottom, 35.0)
                }
                ProgressView()
                    .controlSize(.large)
                    .scaleEffect(1.3, anchor: .center)
                    .progressViewStyle(CircularProgressViewStyle(tint: appearance.spinnerColor))
                    .padding()
                    .onAppear{
                        eNVsdk.caacAnalyticsDelegate?.eventReport(event: CAACAnalyticsEvent.envProgressScreen, properties: nil)
                    }
                Spacer()
                    .frame(height: 35.0)
                if !appearance.text.textContentAboveProgress {
                    Text(timerExpired ? "Verifying your phone number. Please wait..." : "Verifying your phone number...")
                        .multilineTextAlignment(appearance.text.alignment == .center ? .center : .leading )
                        .padding(.top, 15.0)
                }
                AnyView(self.getSecondaryButton(buttonStyle: appearance.secondaryButtonStyle)
                    .opacity(timerExpired ? 1.0 : 0.0)
                    .disabled(!timerExpired))
            }
            .padding(.horizontal, appearance.text.sideSpacing)
            .padding(.vertical)
        }
        .onAppear {
            SDKLogger.debug("Progressing View appeared")
            if proceedWithENV {
                startTimer()
                startENV()
            }
            else {
                SDKLogger.debug("Error View appeared")
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(AnyView(appearance.backgroundStyle))
        .navigationBarBackButtonHidden(true)
        .foregroundColor(appearance.textColor)
        .environment(\.font, appearance.getTextFont())
        .alert(isPresented: $showingAlert) {
           
                return Alert(title: Text("You are about to exit the app"),
                             primaryButton: Alert.Button.default(Text("Exit now")) {
                    eNVsdk.caacAnalyticsDelegate?.eventReport(event: .envVerificationProgressCancellationPositiveButton, properties: nil)
                    self.timerExpired = false
                    eNVsdk.sendErrorResponseWithAppCallbackUrl(
                        error: ErrorModel(errorCode: .user_activity, errorDescription: .USER_CANCELLED),
                        appurl: eNVsdk.uLinkModel?.appCallbackUrl
                    ) {
                        // Once the URL has been opened (or failed), exit the app:
                        eNVsdk.exitApp()
                    }
                    
                },
                             secondaryButton: Alert.Button.cancel(){
                    eNVsdk.caacAnalyticsDelegate?.eventReport(event: .envVerificationProgressCancellationNegativeButton, properties: nil)
                })
            
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.didEnterBackgroundNotification)) {_ in
            eNVsdk.exitApp()
        }
    }
    
    func startTimer() { //timer expires after a few seconds
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5 , execute: {self.timerExpired = true})
    }
    
    func getSecondaryButton(buttonStyle: some ButtonStyle) -> some View {
        return Button(action: {
            eNVsdk.caacAnalyticsDelegate?.eventReport(event: .envVerificationProgressCancelledButton, properties: nil)
            showingAlert = true
        })
        {
            Text("Cancel Number Verification",  bundle: appearance.bundle)
        }
        .buttonStyle(buttonStyle)
        .padding(.vertical, 15.0)
        
    }
    
    func startENV() {
        eNVsdk.performNumberVerification()
    }
    
}

@available(iOS 18.0, *)
#Preview("Loading") {
    let appearance =  ENVAppearance()
    return ENVContentView()
        .environmentObject(appearance)
        .environmentObject(MockSDK(wantedState: MockSDK.MockState.loading) as CAACSDK)
}

@available(iOS 18.0, *)
#Preview("Loading Cloud") {
    let appearance =  ENVAppearance()
    appearance.text.cspName = "Cloud™"
    appearance.text.sideSpacing = 20
    appearance.images.contentLogo = Image(systemName: "cloud")
    appearance.textColor = Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor.white : UIColor.darkGray })
    appearance.backgroundStyle = LinearGradient(
        gradient: Gradient(stops: [
            Gradient.Stop(color: Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(hexString: "#0F2027") : UIColor(hexString: "#FFFFFF") }),location: 0.4),
            Gradient.Stop(color: Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(hexString: "#203A43") : UIColor(hexString: "#eafff0") }),location: 0.7),
            Gradient.Stop(color: Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(hexString: "#2C5364") : UIColor(hexString: "#6dd5ed") }),location: 0.95),
        ]),
        startPoint: .bottomLeading, endPoint: .topTrailing).ignoresSafeArea()
    return ENVContentView()
        .environmentObject(appearance)
        .environmentObject(MockSDK(wantedState: MockSDK.MockState.loading) as CAACSDK)
}

@available(iOS 18.0, *)
#Preview("Loading Cloud Leading") {
    let appearance =  ENVAppearance()
    appearance.text.cspName = "Cloud™"
    appearance.text.alignment = .leading
    appearance.text.sideSpacing = 20
    appearance.images.contentLogo = Image(systemName: "cloud")
    appearance.textColor = Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor.white : UIColor.darkGray })
    appearance.backgroundStyle = LinearGradient(
        gradient: Gradient(stops: [
            Gradient.Stop(color: Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(hexString: "#0F2027") : UIColor(hexString: "#FFFFFF") }),location: 0.4),
            Gradient.Stop(color: Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(hexString: "#203A43") : UIColor(hexString: "#eafff0") }),location: 0.7),
            Gradient.Stop(color: Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(hexString: "#2C5364") : UIColor(hexString: "#6dd5ed") }),location: 0.95),
        ]),
        startPoint: .bottomLeading, endPoint: .topTrailing).ignoresSafeArea()
    return ENVContentView()
        .environmentObject(appearance)
        .environmentObject(MockSDK(wantedState: MockSDK.MockState.loading) as CAACSDK)
}
