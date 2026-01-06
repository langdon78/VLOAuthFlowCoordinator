//
//  OAuthTokenStorageManager.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 11/23/25.
//

class OAuthTokenStorageManager {
    enum TokenType: String {
        case accessToken = "oauth_access_token"
        case accessTokenSecret = "oauth_access_token_secret"
        case requestTokenSecret = "oauth_request_token_secret"
    }
    
    let keychainManager: KeychainManager
    
    init(keychainManager: KeychainManager) {
        self.keychainManager = keychainManager
    }
    
    // MARK: - Save Tokens
    func save(_ token: String, for tokenType: TokenType) -> Bool {
        save(token, for: tokenType.rawValue)
    }
    
    func save(_ token: String, for key: String) -> Bool {
        keychainManager.save(key: key, string: token)
    }
    
    // MARK: - Get Tokens
    func get(tokenType: TokenType) -> String? {
        getToken(for: tokenType.rawValue)
    }
    
    func getToken(for key: String) -> String? {
        keychainManager.loadString(key: key)
    }
    
    // MARK: - Delete Tokens
    func delete(tokenType: TokenType) -> Bool {
        deleteToken(for: tokenType.rawValue)
    }
    
    func deleteToken(for key: String) -> Bool {
        keychainManager.delete(key: key)
    }
}
