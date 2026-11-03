// keyhop-auth: Touch ID-gated key agreement with a Secure Enclave key.
//
//   keyhop-auth create [--biometry-only]   -> {"seKey": b64, "peer": b64}
//   keyhop-auth derive <unlock|change|grant>     stdin {"seKey", "peer"} -> b64 secret
//
// The Secure Enclave key never leaves this Mac's Secure Enclave; seKey is an
// opaque blob only that Secure Enclave can use. derive agrees it with a
// software public key ("peer", whose private half was discarded at create), so
// the secret can only be recomputed here, after Touch ID (or the login
// password, unless created with --biometry-only).
//
// Exit codes: 0 ok, 1 error, 2 cancelled or failed authentication.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

let cancelledExit: Int32 = 2

func fail(_ message: String, code: Int32 = 1) -> Never {
  FileHandle.standardError.write(Data((message + "\n").utf8))
  exit(code)
}

func readInput() -> [String: Any] {
  let data = FileHandle.standardInput.readDataToEndOfFile()
  guard let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
    fail("Expected a JSON object on stdin.")
  }
  return object
}

// Fixed prompts: callers choose an action, never the wording.
func reason(for action: String) -> String {
  switch action {
  case "unlock": return "unlock your keyhop vault"
  case "change": return "change which tools may use your keyhop secrets"
  case "grant": return "let Claude run the command you just approved with your keyhop secrets"
  default: fail("Unknown action: \(action)")
  }
}

func isCancellation(_ error: Error) -> Bool {
  let ns = error as NSError
  if ns.domain == LAErrorDomain {
    let cancelled: [LAError.Code] = [.userCancel, .systemCancel, .appCancel, .userFallback, .authenticationFailed]
    return cancelled.map { $0.rawValue }.contains(ns.code)
  }
  return ns.domain == NSOSStatusErrorDomain && ns.code == Int(errSecUserCanceled)
}

/// Prompts once; the evaluated context then satisfies the key's access control.
func authenticate(_ context: LAContext, biometryOnly: Bool, reason: String) {
  let policy: LAPolicy = biometryOnly ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthentication
  var canError: NSError?
  guard context.canEvaluatePolicy(policy, error: &canError) else {
    fail("Touch ID is not available: \(canError?.localizedDescription ?? "unknown reason")")
  }
  let done = DispatchSemaphore(value: 0)
  var result: Error?
  context.evaluatePolicy(policy, localizedReason: reason) { ok, error in
    if !ok { result = error ?? NSError(domain: LAErrorDomain, code: LAError.Code.authenticationFailed.rawValue) }
    done.signal()
  }
  done.wait()
  if let error = result {
    if isCancellation(error) { fail("Authentication was cancelled.", code: cancelledExit) }
    fail("Authentication failed: \(error.localizedDescription)")
  }
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard let command = arguments.first else {
  fail("Usage: keyhop-auth create [--biometry-only] | derive <unlock|change|grant>")
}

switch command {
case "create":
  guard SecureEnclave.isAvailable else { fail("This Mac has no Secure Enclave.") }
  let biometryOnly = arguments.contains("--biometry-only")
  var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
  flags.insert(biometryOnly ? .biometryCurrentSet : .userPresence)
  var accessError: Unmanaged<CFError>?
  guard let access = SecAccessControlCreateWithFlags(
    nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &accessError)
  else {
    fail("Could not create access control: \(accessError!.takeRetainedValue().localizedDescription)")
  }
  do {
    let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
    let peer = P256.KeyAgreement.PrivateKey()
    let output: [String: Any] = [
      "seKey": key.dataRepresentation.base64EncodedString(),
      "peer": peer.publicKey.rawRepresentation.base64EncodedString(),
    ]
    let json = try JSONSerialization.data(withJSONObject: output)
    print(String(decoding: json, as: UTF8.self))
  } catch {
    fail("Could not create a Secure Enclave key: \(error.localizedDescription)")
  }

case "derive":
  let prompt = reason(for: arguments.count > 1 ? arguments[1] : "unlock")
  let input = readInput()
  guard let seKey = (input["seKey"] as? String).flatMap({ Data(base64Encoded: $0) }),
    let peerData = (input["peer"] as? String).flatMap({ Data(base64Encoded: $0) })
  else { fail("Input needs seKey and peer.") }
  let context = LAContext()
  context.localizedReason = prompt
  authenticate(context, biometryOnly: (input["biometryOnly"] as? Bool) ?? false, reason: prompt)
  do {
    let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
      dataRepresentation: seKey, authenticationContext: context)
    let peer = try P256.KeyAgreement.PublicKey(rawRepresentation: peerData)
    let shared = try key.sharedSecretFromKeyAgreement(with: peer)
    print(shared.withUnsafeBytes { Data($0) }.base64EncodedString())
  } catch {
    if isCancellation(error) { fail("Authentication was cancelled.", code: cancelledExit) }
    fail("Could not use the Secure Enclave key: \(error.localizedDescription)")
  }

default:
  fail("Unknown command: \(command)")
}
