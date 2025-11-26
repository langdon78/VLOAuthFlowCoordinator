//
//  OAuthTokenStorageManager.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 11/23/25.
//

public class OAuthTokenStorageManager {
    private enum TokenType: String {
        case accessToken = "oauth_access_token"
        case accessTokenSecret = "oauth_access_token_secret"
        case requestTokenSecret = "oauth_request_token_secret"
    }
    
    public init() {}
    
    // MARK: - Save Tokens
    func saveAccessToken(_ token: String) -> Bool {
        return KeychainHelper.save(key: TokenType.accessToken.rawValue, string: token)
    }
    
    func saveAccessTokenSecret(_ token: String) -> Bool {
        return KeychainHelper.save(key: TokenType.accessTokenSecret.rawValue, string: token)
    }
    
    func saveRequestTokenSecret(_ secret: String) -> Bool {
        return KeychainHelper.save(key: TokenType.requestTokenSecret.rawValue, string: secret)
    }
    
    // MARK: - Get Tokens
    func getAccessToken() -> String? {
        return KeychainHelper.loadString(key: TokenType.accessToken.rawValue)
    }
    
    func getAccessTokenSecret() -> String? {
        return KeychainHelper.loadString(key: TokenType.accessTokenSecret.rawValue)
    }
    
    func getRequestTokenSecret() -> String? {
        return KeychainHelper.loadString(key: TokenType.requestTokenSecret.rawValue)
    }
    
    // MARK: - Clear Tokens
    func clearAllTokens() {
        KeychainHelper.delete(key: TokenType.accessToken.rawValue)
        KeychainHelper.delete(key: TokenType.accessTokenSecret.rawValue)
        KeychainHelper.delete(key: TokenType.requestTokenSecret.rawValue)
    }
    
    // MARK: - Token Validation
    func hasValidTokens() -> Bool {
        return getAccessToken() != nil && getRequestTokenSecret() != nil
    }
}
