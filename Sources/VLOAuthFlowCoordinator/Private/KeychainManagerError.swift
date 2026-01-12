//
//  KeychainManagerError.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 1/11/26.
//

import Security
import Foundation

enum KeychainManagerError: Error, LocalizedError {
    case securityError(OSStatus)
    case unableToConvertStringToData(String)
    
    var errorMessage: String {
        switch self {
        case .securityError(let status):
            if let cfString = SecCopyErrorMessageString(status, nil) {
                return cfString as String
            } else {
                return "Keychain error with status code: \(status)"
            }
        case .unableToConvertStringToData(let value):
            return "Unable to convert \(value) to Data"
        }
    }
    
    // LocalizedError protocol property
    var errorDescription: String? {
        return errorMessage
    }
}
