//
//  main.swift
//  tlsconnection
//
//  Created by Steven Rockarts on 2025-08-12.
// Create a TCP socket connection to httpbin.org:443
// Perform TLS handshake using Swift's Network framework
// Print "TLS connection established!" when successful
// Handle connection failures gracefully

import Foundation
import Network
import Security

let args = CommandLine.arguments

print(args[1])
print(args[2])
let host = NWEndpoint.Host(args[1])
let port =  NWEndpoint.Port(args[2])
 

func createTLSParametersWithALPN() -> NWParameters {
    let tlsOptions = NWProtocolTLS.Options()
    
    //Set the protocol options
    sec_protocol_options_add_tls_application_protocol(tlsOptions.securityProtocolOptions, "h2")
    sec_protocol_options_add_tls_application_protocol(tlsOptions.securityProtocolOptions, "http/1.1")
    
    let tcpOptions = NWProtocolTCP.Options()
    let parameters = NWParameters(tls: tlsOptions, tcp: tcpOptions)
    
    return parameters
}

let parameters = createTLSParametersWithALPN()
let connection = NWConnection(host: host, port: port!, using: parameters)

connection.stateUpdateHandler = { state in
    switch state {
    case .ready:
        print("TLS connection established!")
        print("Negotiated protocol: \(extractNegotiatedALPN(from: connection) ?? "")")
        print("Ready for HTTP/2!")
        connection.cancel()
        exit(0)
    case .failed(let error):
        print("TLS connection failed: \(error)")
        exit(1)
    case .setup:
        print("TLS connection setup in progress...")
    case .waiting(_):
        print("TLS connection waiting for further events...")
    case .preparing:
        print("Connecting to \(host):\(port ?? 0)...")
    case .cancelled:
        print("TLS connection cancelled...")
    @unknown default:
        break
    }
}

connection.start(queue: .main)


RunLoop.main.run()


private func extractNegotiatedALPN(from connection: NWConnection) -> String? {
    guard let tlsMetadata = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
        return nil
    }
    
    guard let negotiatedProtocolPtr = sec_protocol_metadata_get_negotiated_protocol(
        tlsMetadata.securityProtocolMetadata
    ) else {
        return nil
    }
    
    return String(cString: negotiatedProtocolPtr)
}
