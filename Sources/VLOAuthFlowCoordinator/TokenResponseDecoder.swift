//
//  TokenResponseDecoder.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 8/13/25.
//

import Foundation
import VLNetworkingClient

final class TokenResponseDecoder: ResponseBodyDecoder {
    
    func decode<T>(_ type: T.Type, from data: Data) throws -> T where T : Decodable {
        guard let responseString = String(data: data, encoding: .utf8) else { throw NetworkError.noData }
        let params = parseOAuthResponse(responseString)
        return OAuthToken(
            token: params["oauth_token"] ?? "",
            tokenSecret: params["oauth_token_secret"] ?? "",
            callbackConfirmed: params["oauth_callback_confirmed"] == "false"
        ) as! T
    }
    
    func parseOAuthResponse(_ responseString: String) -> [String: String] {
        let pairs = responseString.components(separatedBy: "&")
        var result: [String: String] = [:]
        
        for pair in pairs {
            let keyValue = pair.components(separatedBy: "=")
            if keyValue.count == 2 {
                let key = keyValue[0]
                let value = keyValue[1].removingPercentEncoding ?? keyValue[1]
                result[key] = value
            }
        }
        
        return result
    }
    
}
