//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  ENVAppearance.swift
//  sdk
//
//  Created by Kotronis Dimitrios on 23/11/23.
//

import Combine
import Foundation
import SwiftUI
/**
 Class used to customize the ``CAACView`` appearance and its subsequent views.
*/
public class ENVAppearance: ObservableObject  {
    
    /// Contains image properties that will be used in the number verification screens.
    public var images:ENVAppearanceImages = ENVAppearanceImages()
    /// Contains properties that can customize how text is displayed.
    public var text:AppearanceText = AppearanceText()
    /// Bundle to be used for strings. By default, Bundle.main is used.
    public var bundle: Bundle = Bundle.main
    /// Color used in the spinner when number verification process starts
    public var spinnerColor = Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(hexString: "FFD4B9") : UIColor(hexString: "FF5757")})
    /// Color used for text.
    public var textColor = Color(UIColor { $0.userInterfaceStyle == .dark ?  UIColor(hexString: "F0F0F0") : UIColor(hexString: "333333")})
    /// Color used in the failure icon
    public var failureIconColor = Color(UIColor(hexString: "ff3232"))
    /// Use backgroundStyle like Color, LinearGradient, Image to customize the background.
    public var backgroundStyle: any View = Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(.black) : UIColor(.white)})
//    public var accentColor = Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(.white) : UIColor(.blue)})
    /// Button style used for `Begin Verification` button used to consent on number verification.
    public var primaryButtonStyle: any ButtonStyle
    /// Button style used for `I do not want to continue` button used to decline number verification.
    public var secondaryButtonStyle: any ButtonStyle
    
    public init(){
        self.primaryButtonStyle = PrimaryButtonStyleEnv(accentColor: Color.blue, btnTxtColor: Color.white)
        self.secondaryButtonStyle = SecondaryButtonStyleEnv(accentColor: Color.blue)
    }
    
    func getTextFont() -> Font {
        guard let textFontName = text.textFontName else { return .system(.body, design: .default)}
        return .custom(textFontName, size: text.textFontSize)
    }
    func getTitleFont() -> Font {
        guard let textFontName = text.textFontName else { return .system(.title, design: .default)}
        return .custom(textFontName, size: text.titleFontSize)
    }
    
}

struct PrimaryButtonStyleEnv: ButtonStyle{
    let accentColor: Color
    let btnTxtColor: Color
    init(accentColor : Color, btnTxtColor: Color) {
        self.accentColor = accentColor
        self.btnTxtColor = btnTxtColor
    }
    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.callout)
            .frame(minWidth: 0, maxWidth: .infinity)
            .padding()
            .foregroundColor(self.btnTxtColor)
            .background(
                self.accentColor
                    .clipShape(RoundedRectangle(cornerRadius: 25))
            )
            .padding(.horizontal, 20.0)
    }
}

struct SecondaryButtonStyleEnv: ButtonStyle{
    let accentColor: Color
    init(accentColor : Color) {
        self.accentColor = accentColor
    }
    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding()
            .foregroundColor(self.accentColor)
    }
}

extension UIColor {
    convenience init(hexString: String) {
        let hex = hexString.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int = UInt64()
        Scanner(string: hex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch hex.count {
        case 3: // RGB (12-bit)
            (a, r, g, b) = (255, (int >> 8) * 17, (int >> 4 & 0xF) * 17, (int & 0xF) * 17)
        case 6: // RGB (24-bit)
            (a, r, g, b) = (255, int >> 16, int >> 8 & 0xFF, int & 0xFF)
        case 8: // ARGB (32-bit)
            (a, r, g, b) = (int >> 24, int >> 16 & 0xFF, int >> 8 & 0xFF, int & 0xFF)
        default:
            (a, r, g, b) = (255, 0, 0, 0)
        }
        self.init(red: CGFloat(r) / 255, green: CGFloat(g) / 255, blue: CGFloat(b) / 255, alpha: CGFloat(a) / 255)
    }
}

#Preview ("Cirle") {
    let eNVAppearance: ENVAppearance = ENVAppearance()
    eNVAppearance.backgroundStyle = Image(.imgPlaceholder).resizable().scaledToFit().scaleEffect(CGSize(width: 0.5, height: 0.5))
    
    func getButton(text:String, buttonStyle: some ButtonStyle) -> some View {
        return Button(text, action: {})
            .buttonStyle(buttonStyle)
    }
    
    return ZStack{
        VStack {
            Spacer()
            Text("Some test text")
            Spacer()
            AnyView(getButton(text: " Primary", buttonStyle: eNVAppearance.primaryButtonStyle))
            AnyView(getButton(text: " Secondary", buttonStyle: eNVAppearance.secondaryButtonStyle))
            Spacer()
        }
    }
    .background(eNVAppearance.backgroundStyle)    
}

