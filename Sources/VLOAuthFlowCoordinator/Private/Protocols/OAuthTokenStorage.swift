//
//  OAuthTokenStorage.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 1/11/26.
//

protocol OAuthTokenStorage: Actor {
    func save(_ token: String, for tokenType: OAuthTokenStorageManager.TokenType) async throws
    func save(_ token: String, for key: String) async throws
    func get(tokenType: OAuthTokenStorageManager.TokenType) async throws -> String?
    func getToken(for key: String) async throws -> String?
    func delete(tokenType: OAuthTokenStorageManager.TokenType) async throws
    func deleteToken(for key: String) async throws
}
