//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  ConsentView.swift
//  sdk
//

import LocalAuthentication
import SwiftUI
import SystemConfiguration

/**
 It's the screen to be displayed when the ENV operation need to be initiated.

 > Requires: ENVSDK and ENVAppearance have to be passed as environmentObject in the view.

 ```
 // Initializing SDK
 let eNVSdk = let ENVSDK(...)
 let appearance: ENVAppearance = ENVAppearance()
 
 ENVConsentView().environmentObject(eNVSdk).environmentObject(appearance)
 ```
 */
struct ENVConsentView: View {
    
    enum AlertType: Identifiable {
        case connectionError
        case exitApp
        
        var id: Int {
            switch self {
            case .connectionError:
                return 0
            case .exitApp:
                return 1
            }
        }
    }
    
    private var eNVsdk: CAACSDK
    @EnvironmentObject private var appearance: ENVAppearance
    @Environment(\.locale) var sdkLocale
    @Environment(\.font) var sdkFont
    
    @State private var ongoingProcedure: Bool = false
    @State private var cancelIsPressed: Bool = false
    @State private var showProgressBar: Bool = false
    @State private var alertToShow: AlertType? = nil
    @State private var action: Int? = 0
    @State private var activeRemainingTime = 20 //initial remaining time
    
    private let countdownTimer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
    private var appName: String
    
    public init(eNVsdk: CAACSDK){
        self.eNVsdk = eNVsdk
        self.appName = eNVsdk.uLinkModel?.appName ?? "an"
    }
    
    public var body: some View {
        NavigationStack {
            HStack() {
                Spacer().frame(width: appearance.text.sideSpacing)
                VStack(alignment: appearance.text.alignment) {
                    Group {
                        Spacer()
                            .frame(height: 25)
                        appearance.images.consentLogo
                            .renderingMode(.original)
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .padding(.top, 10)
                            .padding(.horizontal, appearance.images.consentLogoHorizontalSpacing)
                            .frame(height: 150)
                        Spacer()
                            .frame(height: 50)
                        Text("You are using \(appName) application asking to verify your \(appearance.text.cspName) number.\n Press \"Begin Verification\" to start.", bundle: appearance.bundle)
                            .multilineTextAlignment(appearance.text.alignment == .center ? .center : .leading)
                            .lineLimit(nil)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.vertical, 15)
                            .padding(.horizontal, 15)
                        Text("You only need to do this occasionally.", bundle: appearance.bundle)
                            .multilineTextAlignment(appearance.text.alignment == .center ? .center : .leading )
                            .padding(.vertical, 15.0)
                        Text("Simplified verification means\nno more SMS interruptions.", bundle: appearance.bundle)
                            .multilineTextAlignment(appearance.text.alignment == .center ? .center : .leading )
                            .lineLimit(nil)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.vertical, 15.0)
                        if self.showProgressBar {
                            ProgressView()
                                .controlSize(.large)
                                .scaleEffect(1.3, anchor: .center)
                                .progressViewStyle(CircularProgressViewStyle(tint: appearance.spinnerColor))
                                .padding()
                        }
                        Spacer()
                    }
                    .onReceive(countdownTimer) { _ in
                        if activeRemainingTime > 0 {
                            activeRemainingTime -= 1
                        }
                        else {
                            eNVsdk.caacAnalyticsDelegate?.eventReport(event: .envConsentTimedOutEvent, properties: nil)
                            countdownTimer.upstream.connect().cancel()
                            self.showProgressBar = true  // show progress bar
                            self.cancelIsPressed = true  // buttons shall be disabled
                            self.ongoingProcedure = true // buttons shall be disabled
                            
                            eNVsdk.sendErrorResponseWithAppCallbackUrl(
                                error: ErrorModel(errorCode: .user_activity, errorDescription: .TIME_OUT),
                                appurl: eNVsdk.uLinkModel?.appCallbackUrl
                            ) {
                                // Once the URL has been opened (or failed), exit the app:
                                eNVsdk.exitApp()
                            }
                        }
                    }
                    AnyView(self.getPrimaryButton(buttonStyle: appearance.primaryButtonStyle))
                    AnyView(self.getSecondaryButton(buttonStyle: appearance.secondaryButtonStyle))
                    
                    Spacer()
                        .frame(height: 25.0)
                }
                if(appearance.text.alignment == .center){
                    Spacer().frame(width: appearance.text.sideSpacing)
                } else {
                    Spacer(minLength: appearance.text.sideSpacing)
                }
            }
            .navigationDestination(isPresented: Binding(
                            get: { action == 1 },
                            set: { if !$0 { action = nil } }
                        )) {
                            ENVContentView()
                                .environment(\.locale, sdkLocale)
                                .environmentObject(appearance)
                                .environmentObject(eNVsdk)
                        }
        }
        .frame(minWidth: 0, maxWidth: .infinity)
        .background(AnyView(appearance.backgroundStyle))
        .navigationBarBackButtonHidden(true)
        .navigationViewStyle(StackNavigationViewStyle())
        .foregroundColor(appearance.textColor)
        .alert(item: $alertToShow) { alertType in
            switch alertType {
            case .connectionError:
                return Alert(title: Text("No Internet Connection"),
                             message: Text("Please check your internet connection and try again"),
                             dismissButton: .default(Text("Close")) {
                    self.ongoingProcedure = false
                })
            case .exitApp:
                return Alert(title: Text("You are about to exit the app"),
                             primaryButton: Alert.Button.default(Text("Exit now")) {
                    eNVsdk.caacAnalyticsDelegate?.eventReport(event: .envConsentDeclinePositiveButton, properties: nil)
                    countdownTimer.upstream.connect().cancel()
                    self.showProgressBar = true  // show progress bar
                    self.cancelIsPressed = true  // buttons shall be disabled
                    self.ongoingProcedure = true // buttons shall be disabled
                    
                    eNVsdk.sendErrorResponseWithAppCallbackUrl(
                        error: ErrorModel(errorCode: .user_activity, errorDescription: .USER_CANCELLED),
                        appurl: eNVsdk.uLinkModel?.appCallbackUrl
                    ) {
                        // Once the URL has been opened (or failed), exit the app:
                        eNVsdk.exitApp()
                    }
                },
                             secondaryButton: Alert.Button.cancel(){
                    eNVsdk.caacAnalyticsDelegate?.eventReport(event: .envConsentDeclineNegativeButton, properties: nil)
                    self.cancelIsPressed = false
                }
                )
            }
        }
        .environment(\.font, appearance.getTextFont())
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.didEnterBackgroundNotification)) {_ in
            eNVsdk.exitApp()
        }.onAppear(){
            // leave here the printing of the network in order to trigger it for the first time
            // otherwise the first result will be false, despite the fact that the network is reachable
            SDKLogger.debug("isNetworkReachable: \(eNVsdk.isNetworkReachable())")
            
            eNVsdk.caacAnalyticsDelegate?.eventReport(event: .envConsentScreen, properties: nil)
        }
    }
    
    func getPrimaryButton(buttonStyle: some ButtonStyle) -> some View {
        return Button(action: {
            self.ongoingProcedure = true
            if eNVsdk.isNetworkReachable() {
                eNVsdk.caacAnalyticsDelegate?.eventReport(event: .envConsentButton, properties: ["noInternet": false])
                authenticateTapped()
                countdownTimer.upstream.connect().cancel()
            }
            else {
                eNVsdk.caacAnalyticsDelegate?.eventReport(event: .envConsentButton, properties: ["noInternet": true])
                alertToShow = .connectionError
            }
            
        }) {
            Text("Begin Verification", bundle: appearance.bundle)
        }
        .buttonStyle(buttonStyle)
        .padding(.vertical,20.0)
        .disabled(cancelIsPressed)
    }
    
    func getSecondaryButton(buttonStyle: some ButtonStyle) -> some View {
        return Button(action: {
            eNVsdk.caacAnalyticsDelegate?.eventReport(event: .envConsentDeclineButton, properties: nil)
            self.cancelIsPressed = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
                if !self.ongoingProcedure { //if BeginVerification is not pressed already
                    alertToShow = .exitApp
                }
            }
        })
        {
            Text("I do not want to continue (\(activeRemainingTime))",  bundle: appearance.bundle)
        }
        .buttonStyle(buttonStyle)
        .padding(.vertical, 15.0)
        .disabled(ongoingProcedure)
    }
    
    func authenticateTapped() {
        action = 1
    }
    
}

#Preview("Default") {
    let appearance: ENVAppearance = {
        let a = ENVAppearance()
        a.text.cspName = "CSP Name"
        a.text.sideSpacing = 10
        return a
    }()

    ENVConsentView(eNVsdk: CAACSDK())
        .environmentObject(appearance)
}

#Preview("Default left") {
    let appearance: ENVAppearance = {
        let a = ENVAppearance()
        a.text.cspName = "CSP Name"
        a.text.alignment = .leading
        a.text.sideSpacing = 20
        return a
    }()

    ENVConsentView(eNVsdk: CAACSDK())
        .environmentObject(appearance)
}

#Preview("Aduna") {
    struct AdPrimaryButtonStyle: ButtonStyle{
        public func makeBody(configuration: Configuration) -> some View {
            configuration.label
                .font(.body.bold())
                .frame(minWidth: 0, maxWidth: .infinity)
                .padding()
                .foregroundColor(Color.white)
                .background(
                    Color.blue
                        .clipShape(RoundedRectangle(cornerRadius: 5))
                )
        }
    }
    struct AdSecondaryButtonStyle: ButtonStyle{
        public func makeBody(configuration: Configuration) -> some View {
            configuration.label
                .padding()
                .foregroundColor(Color.blue)
        }
    }
    
    let appearance =  ENVAppearance()
    appearance.text.cspName = "Aduna"
    appearance.text.sideSpacing = 20
    appearance.primaryButtonStyle = AdPrimaryButtonStyle()
    appearance.secondaryButtonStyle = AdSecondaryButtonStyle()
    appearance.backgroundStyle = Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor.darkGray : UIColor.white }).ignoresSafeArea()
    
    let sdk = CAACSDK()

    
    let consentView = ENVConsentView(eNVsdk: sdk)
        .environmentObject(appearance)
    return consentView
}

struct AdPrimaryButtonStyle: ButtonStyle {
    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.bold))
            .frame(minWidth:0, maxWidth: .infinity)
            .padding()
            .foregroundStyle(Color.white)
            .background(
                RoundedRectangle(cornerRadius: 5)
                    .fill(Color.blue.opacity(configuration.isPressed ? 0.85 : 1.0))
            )
            .animation(.easeInOut(duration: 0.12), value: configuration.isPressed)
    }
}

struct AdSecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.semibold))
            .frame(maxWidth: .infinity)
            .padding()
            .foregroundStyle(Color.blue)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color.blue, lineWidth: 1)
                    .opacity(configuration.isPressed ? 0.6 : 1.0)
            )
            .scaleEffect(configuration.isPressed ? 0.98 : 1.0)
            .animation(.easeInOut(duration: 0.12), value: configuration.isPressed)
    }
}



#Preview("Aduna left") {
    let appearance: ENVAppearance = {
        let a = ENVAppearance()
        a.images.consentLogo = Image(.imgPlaceholder)
        a.text.cspName = "Aduna"
        a.text.alignment = .leading
        a.text.sideSpacing = 20
        a.text.textFontName = UIFont.systemFont(ofSize: 18).familyName
        a.text.textFontSize = 18
        a.text.titleFontSize = 24
        a.primaryButtonStyle = AdPrimaryButtonStyle()
        a.secondaryButtonStyle = AdSecondaryButtonStyle()
        a.backgroundStyle = Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor.darkGray : UIColor.white }).ignoresSafeArea()
        return a
    }()

    let sdk = CAACSDK()
    
    let consentView = ENVConsentView(eNVsdk: sdk)
        .environmentObject(appearance)
    consentView
}

fileprivate struct DarkSamplePrimaryButtonStyle: ButtonStyle{
    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.bold())
            .padding()
            .foregroundColor( Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor.darkGray : UIColor(hexString: "#eafff0") }))
            .background(
                Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(hexString: "#eafff0") : UIColor(hexString: "#0F2027") })
                    .clipShape(RoundedRectangle(cornerRadius: 25))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 25)
                    .stroke( Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(hexString: "#2C5364") : UIColor(hexString: "#2C5364") }), lineWidth: 5)
            )
    }
}

fileprivate struct DarkSampleSecondaryButtonStyle: ButtonStyle{
    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding()
            .foregroundColor(Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(hexString: "#eafff0") : UIColor(hexString: "#2C5364") }))
    }
}

#Preview("Cloud") {
    let appearance =  ENVAppearance()
    appearance.text.cspName = "Cloud™"
    appearance.text.sideSpacing = 20
    appearance.images.consentLogo = Image(systemName: "cloud")
    appearance.textColor = Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor.white : UIColor.darkGray })
    appearance.primaryButtonStyle = DarkSamplePrimaryButtonStyle()
    appearance.secondaryButtonStyle = DarkSampleSecondaryButtonStyle()
    appearance.backgroundStyle = LinearGradient(
        gradient: Gradient(stops: [
            Gradient.Stop(color: Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(hexString: "#0F2027") : UIColor(hexString: "#FFFFFF") }),location: 0.4),
            Gradient.Stop(color: Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(hexString: "#203A43") : UIColor(hexString: "#eafff0") }),location: 0.7),
            Gradient.Stop(color: Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(hexString: "#2C5364") : UIColor(hexString: "#6dd5ed") }),location: 0.95),
        ]),
        startPoint: .bottomLeading, endPoint: .topTrailing).ignoresSafeArea()
    let sdk = CAACSDK()
    let consentView = ENVConsentView(eNVsdk: sdk)
        .environmentObject(appearance)
    return consentView
}


#Preview("Cloud left") {
    let appearance =  ENVAppearance()
    appearance.text.alignment = .leading
    appearance.text.sideSpacing = 20
    appearance.text.cspName = "Cloud™"
    appearance.images.consentLogo = Image(systemName: "cloud")
    appearance.textColor = Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor.white : UIColor.darkGray })
    appearance.primaryButtonStyle = DarkSamplePrimaryButtonStyle()
    appearance.secondaryButtonStyle = DarkSampleSecondaryButtonStyle()
    appearance.backgroundStyle = LinearGradient(
        gradient: Gradient(stops: [
            Gradient.Stop(color: Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(hexString: "#0F2027") : UIColor(hexString: "#FFFFFF") }),location: 0.4),
            Gradient.Stop(color: Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(hexString: "#203A43") : UIColor(hexString: "#eafff0") }),location: 0.7),
            Gradient.Stop(color: Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(hexString: "#2C5364") : UIColor(hexString: "#6dd5ed") }),location: 0.95),
        ]),
        startPoint: .bottomLeading, endPoint: .topTrailing).ignoresSafeArea()
    let sdk = CAACSDK()
    let consentView = ENVConsentView(eNVsdk: sdk)
        .environmentObject(appearance)
    
    return consentView
}
