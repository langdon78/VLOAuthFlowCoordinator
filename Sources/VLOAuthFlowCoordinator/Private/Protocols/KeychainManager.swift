//
//  KeychainManager.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 1/4/26.
//

import Foundation

protocol KeychainManager: Actor {
    func save(key: String, data: Data) async throws
    func load(key: String) async throws -> Data?
    func delete(key: String) async throws
}

// String convenience methods
extension KeychainManager {
    func save(key: String, string: String) async throws {
        guard let data = string.data(using: .utf8) else { throw KeychainManagerError.unableToConvertStringToData(string) }
        return try await save(key: key, data: data)
    }
    
    func loadString(key: String) async throws -> String? {
        guard let data = try await load(key: key) else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
