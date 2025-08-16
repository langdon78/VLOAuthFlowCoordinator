//
//  VLOAuthFlowCoordinator.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 8/11/25.
//

import Foundation

class Coordinator {
    let authRequester: AuthRequester
    
    init(authRequester: AuthRequester) {
        self.authRequester = authRequester
    }
}
