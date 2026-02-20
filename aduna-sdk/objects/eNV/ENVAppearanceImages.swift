//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  AppearanceImages.swift
//  sdk
//

import Foundation
import SwiftUI

public class ENVAppearanceImages {
    
    /// Logo to be used in consent screen.
    public var consentLogo:Image = Image(.imgPlaceholder)
    /// Customize logo spacing in consent screen.
    public var consentLogoHorizontalSpacing: CGFloat = 0
    /// Logo to be used in screen indicating the operation progress.
    public var contentLogo:Image = Image(.imgPlaceholder)
    /// Customize logo spacing in operation progress screen.
    public var contentLogoHorizontalSpacing: CGFloat = 0
    /// Icon to be used for failure in verification
    public var failureIcon:Image = Image(.imgPlaceholder)
    /// Customize failure icon horizontal spacing
    public var failureIconHorizontalSpacing: CGFloat = 0

}
