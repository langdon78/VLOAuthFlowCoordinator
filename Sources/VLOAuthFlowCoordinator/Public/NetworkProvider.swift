//
//  NetworkProvider.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 11/23/25.
//

import Foundation

public protocol NetworkProvider {
    func getRequestToken(from request: URLRequest) async throws -> OAuthRequestToken?
    func getAccessToken(from request: URLRequest) async throws -> OAuthAccessToken?
    func decodeVerifierResponse(from authorizationResponseQuery: String) throws -> OAuthVerifier?
}
