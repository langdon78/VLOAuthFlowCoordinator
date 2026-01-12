//
//  AccountTokenStorage.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 1/11/26.
//

protocol AccountTokenStorage: Actor {
    // MARK: Saving Tokens
    func saveAccessToken(_ token: String) async throws
    func saveAccessTokenSecret(_ token: String) async throws
    func saveRequestTokenSecret(_ token: String) async throws
    
    // MARK: Retrieve Tokens
    func getAccessToken() async throws -> String?
    func getAccessTokenSecret() async throws -> String?
    func getRequestTokenSecret() async throws -> String?
    
    // MARK: Clear Tokens
    func clearTokens() async throws
    
    // MARK: Token Validation
    func hasValidTokens() async throws -> Bool
}
