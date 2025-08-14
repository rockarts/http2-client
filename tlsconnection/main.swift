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
let host = NWEndpoint.Host(args[1])
let port =  NWEndpoint.Port(args[2])

func createTLSParametersWithALPN() -> NWParameters {
    let tlsOptions = NWProtocolTLS.Options()
    sec_protocol_options_add_tls_application_protocol(tlsOptions.securityProtocolOptions, "h2")
    sec_protocol_options_add_tls_application_protocol(tlsOptions.securityProtocolOptions, "http/1.1")
    
    let tcpOptions = NWProtocolTCP.Options()
    tcpOptions.connectionTimeout = 5
    let parameters = NWParameters(tls: tlsOptions, tcp: tcpOptions)
    
    return parameters
}

let parameters = createTLSParametersWithALPN()
let connection = NWConnection(host: host, port: port!, using: parameters)

connection.stateUpdateHandler = { state in
    switch state {
    case .ready:
        print("TLS connection established!")
        
        guard verifyConnectionState(connection: connection) else {
            print("Connection state verification failed")
            exit(1)
        }
        
        printTLSDetails(connection: connection)
        
        if let negotiatedProtocol = extractNegotiatedALPN(from: connection) {
            print("Negotiated protocol: \(negotiatedProtocol)")
            
            if negotiatedProtocol == "h2" {
                print("Connection ready for HTTP/2 frame exchange!")
            } else {
                print("Error: HTTP/2 not negotiated, got \(negotiatedProtocol)")
                exit(1)
            }
        } else {
            print("Error: Could not determine negotiated protocol")
            exit(1)
        }
        
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

private func verifyConnectionState(connection: NWConnection) -> Bool {
    guard connection.currentPath != nil else {
        print("No viable network path")
        return false
    }
    
    guard connection.currentPath?.status == .satisfied else {
        print("Network path not satisfied")
        return false
    }
    
    return true
}

private func printTLSDetails(connection: NWConnection) {
    guard let tlsMetadata = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
        print("Could not retrieve TLS metadata")
        return
    }
    
    let securityMetadata = tlsMetadata.securityProtocolMetadata
    
    let tlsVersion = sec_protocol_metadata_get_negotiated_tls_protocol_version(securityMetadata)
    print("TLS Version: \(describeTLSVersion(tlsVersion))")
    
    let cipherSuite = sec_protocol_metadata_get_negotiated_tls_ciphersuite(securityMetadata)
    print("Cipher Suite: \(describeCipherSuite(cipherSuite))")
}

private func describeTLSVersion(_ version: tls_protocol_version_t) -> String {
    switch version {
    case .TLSv10: return "1.0"
    case .TLSv11: return "1.1"
    case .TLSv12: return "1.2"
    case .TLSv13: return "1.3"
    default: return "Unknown"
    }
}

private func describeCipherSuite(_ suite: tls_ciphersuite_t) -> String {
    return "0x\(String(suite.rawValue, radix: 16))"
}
