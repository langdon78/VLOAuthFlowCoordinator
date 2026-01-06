//
//  KeychainManager.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 1/4/26.
//

import Foundation

protocol KeychainManager {
    func save(key: String, data: Data) -> Bool
    func load(key: String) -> Data?
    func delete(key: String) -> Bool
}

// String convenience methods
extension KeychainManager {
    func save(key: String, string: String) -> Bool {
        guard let data = string.data(using: .utf8) else { return false }
        return save(key: key, data: data)
    }
    
    func loadString(key: String) -> String? {
        guard let data = load(key: key) else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
