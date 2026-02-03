//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  AppearanceText.swift
//  sdk
//
//  Created by Kotronis Dimitrios on 24/11/23.
//

import Foundation
import SwiftUI

public class AppearanceText {
    
    /// CSP name to be used.
    public var cspName:String = "..."
    /// Provide a custom FontName if needed.
    public var textFontName: String? = nil
    /// Customize font size. Default is 18.
    public var textFontSize: CGFloat = 18
    /// Customize title font size. Default is 26.
    public var titleFontSize: CGFloat = 26
    /// Customize text alignment, .center .leading are supported.
    public var alignment: HorizontalAlignment = .center
    /// Space between text and screen edges. 
    public var sideSpacing: CGFloat? = 0
    /// If true, text that accompanies progress indicator is placed above progress indicator, otherwise below progress indicator.
    public var textContentAboveProgress: Bool = true
    
}
