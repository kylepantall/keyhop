// keyhop-auth: Touch ID-gated key agreement with a Secure Enclave key.
//
//   keyhop-auth create [--biometry-only]   -> {"seKey": b64, "peer": b64}
//   keyhop-auth derive <unlock|change|grant|bypass>     stdin {"seKey", "peer"} -> b64 secret
//   keyhop-auth ask                         stdin: prompt lines -> deny | once | always
//                                           (the access dialog: who is asking and why, the
//                                           secrets, and the script it will run, highlighted)
//
// The Secure Enclave key never leaves this Mac's Secure Enclave; seKey is an
// opaque blob only that Secure Enclave can use. derive agrees it with a
// software public key ("peer", whose private half was discarded at create), so
// the secret can only be recomputed here, after Touch ID (or the login
// password, unless created with --biometry-only).
//
// Exit codes: 0 ok, 1 error, 2 cancelled or failed authentication.

import AppKit
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
  case "bypass": return "run the shell or interpreter you just approved, once, with your keyhop secrets"
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

// MARK: - Access dialog

/// What keyhop asks the user. keyhop writes it as lines of tab-separated
/// fields, each value base64 UTF-8; every string is fixed wording or already
/// made inert (no line breaks, bidi or invisible characters of the caller's).
struct Prompt {
  var title = "keyhop"
  var headline = ""
  var message = ""
  var reason: String?
  var details: [(String, String)] = []
  var warnings: [String] = []
  var secrets: [(String, String)] = []
  var noScript: String?
  var scriptLabel: String?
  var tokens: [(String, String)] = []
  var footer = ""
  var buttons = "once"
}

func readPrompt() -> Prompt {
  let data = FileHandle.standardInput.readDataToEndOfFile()
  var prompt = Prompt()
  for line in String(decoding: data, as: UTF8.self).split(separator: "\n") {
    let fields = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
    func value(_ index: Int) -> String {
      guard index < fields.count, let bytes = Data(base64Encoded: fields[index]) else { return "" }
      return String(decoding: bytes, as: UTF8.self)
    }
    switch fields.first ?? "" {
    case "title": prompt.title = value(1)
    case "headline": prompt.headline = value(1)
    case "message": prompt.message = value(1)
    case "reason": prompt.reason = value(1)
    case "detail": prompt.details.append((value(1), value(2)))
    case "warning": prompt.warnings.append(value(1))
    case "secret": prompt.secrets.append((value(1), value(2)))
    case "noscript": prompt.noScript = value(1)
    case "scriptlabel": prompt.scriptLabel = value(1)
    case "token": prompt.tokens.append((fields.count > 1 ? fields[1] : "plain", value(2)))
    case "footer": prompt.footer = value(1)
    case "buttons": prompt.buttons = fields.count > 1 && fields[1] == "grant" ? "grant" : "once"
    default: break
    }
  }
  return prompt
}

func highlighted(_ tokens: [(String, String)]) -> NSAttributedString {
  let regular = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
  let bold = NSFont.monospacedSystemFont(ofSize: 12, weight: .semibold)
  let out = NSMutableAttributedString()
  for (kind, text) in tokens {
    var attributes: [NSAttributedString.Key: Any] = [.font: regular, .foregroundColor: NSColor.textColor]
    switch kind {
    case "keyword":
      attributes[.foregroundColor] = NSColor.systemPurple
      attributes[.font] = bold
    case "string": attributes[.foregroundColor] = NSColor.systemRed
    case "number": attributes[.foregroundColor] = NSColor.systemBlue
    case "comment": attributes[.foregroundColor] = NSColor.secondaryLabelColor
    case "gutter": attributes[.foregroundColor] = NSColor.tertiaryLabelColor
    case "hidden":
      // An invisible or reordering character, shown as its escape.
      attributes[.foregroundColor] = NSColor.black
      attributes[.backgroundColor] = NSColor.systemYellow
      attributes[.font] = bold
    default: break
    }
    out.append(NSAttributedString(string: text, attributes: attributes))
  }
  return out
}

/// Escape and the close button deny, like the Deny button.
final class AskPanel: NSPanel {
  var onCancel: (() -> Void)?
  override var canBecomeKey: Bool { true }
  override func cancelOperation(_ sender: Any?) { onCancel?() }
}

final class AskController: NSObject, NSWindowDelegate {
  private(set) var answer = "deny"
  let panel: AskPanel
  private let stack = NSStackView()
  private var sections: [(button: NSButton, content: NSView, title: String)] = []
  private var allowButtons: [NSButton] = []
  private let width: CGFloat = 620

  init(_ prompt: Prompt) {
    panel = AskPanel(
      contentRect: NSRect(x: 0, y: 0, width: 660, height: 300),
      styleMask: [.titled, .closable], backing: .buffered, defer: false)
    super.init()
    panel.title = prompt.title
    panel.level = .modalPanel
    panel.hidesOnDeactivate = false
    panel.isReleasedWhenClosed = false
    panel.delegate = self
    panel.onCancel = { [weak self] in self?.finish("deny") }

    stack.orientation = .vertical
    stack.alignment = .leading
    stack.spacing = 10
    stack.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
    stack.translatesAutoresizingMaskIntoConstraints = false

    stack.addArrangedSubview(label(prompt.headline, font: .boldSystemFont(ofSize: 15)))
    stack.addArrangedSubview(label(prompt.message))
    if let reason = prompt.reason { stack.addArrangedSubview(label(reason, font: .systemFont(ofSize: 13, weight: .medium))) }

    let details = NSStackView()
    details.orientation = .vertical
    details.alignment = .leading
    details.spacing = 3
    for (name, value) in prompt.details {
      details.addArrangedSubview(label("\(name):  \(value)", font: .systemFont(ofSize: 12), color: .secondaryLabelColor))
    }
    stack.addArrangedSubview(details)

    let secrets = NSStackView()
    secrets.orientation = .vertical
    secrets.alignment = .leading
    secrets.spacing = 3
    for (name, how) in prompt.secrets {
      let line = NSMutableAttributedString(
        string: "•  \(name)", attributes: [.font: NSFont.monospacedSystemFont(ofSize: 12, weight: .semibold), .foregroundColor: NSColor.labelColor])
      line.append(NSAttributedString(
        string: "   \(how)", attributes: [.font: NSFont.systemFont(ofSize: 12), .foregroundColor: NSColor.secondaryLabelColor]))
      let field = label("")
      field.attributedStringValue = line
      secrets.addArrangedSubview(field)
    }
    section("Secrets requested (\(prompt.secrets.count))", content: secrets)

    if let scriptLabel = prompt.scriptLabel {
      let box = NSStackView()
      box.orientation = .vertical
      box.alignment = .leading
      box.spacing = 6
      box.addArrangedSubview(label(scriptLabel, font: .systemFont(ofSize: 12), color: .secondaryLabelColor))
      box.addArrangedSubview(scriptView(prompt.tokens))
      section("View script", content: box)
    } else if let noScript = prompt.noScript {
      stack.addArrangedSubview(label("⚠️  " + noScript))
    }

    for warning in prompt.warnings { stack.addArrangedSubview(label("⚠️  " + warning)) }
    stack.addArrangedSubview(label(prompt.footer, font: .systemFont(ofSize: 12), color: .secondaryLabelColor))

    // Deny is the default (Return) and sits where the default button goes.
    let row = NSStackView()
    row.orientation = .horizontal
    row.spacing = 8
    let spacer = NSView()
    spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
    row.addArrangedSubview(spacer)
    let choices = prompt.buttons == "grant"
      ? [("Always allow", "always"), ("Allow once", "once"), ("Deny", "deny")]
      : [("Allow", "once"), ("Deny", "deny")]
    for (title, value) in choices {
      let button = NSButton(title: title, target: self, action: #selector(choose(_:)))
      button.identifier = NSUserInterfaceItemIdentifier(value)
      button.bezelStyle = .rounded
      if value == "deny" {
        button.keyEquivalent = "\r"
      } else {
        // A click meant for whatever was under the mouse can't approve.
        button.isEnabled = false
        allowButtons.append(button)
      }
      row.addArrangedSubview(button)
    }
    row.translatesAutoresizingMaskIntoConstraints = false
    stack.addArrangedSubview(row)
    row.widthAnchor.constraint(equalToConstant: width).isActive = true

    let content = NSView()
    content.addSubview(stack)
    NSLayoutConstraint.activate([
      stack.leadingAnchor.constraint(equalTo: content.leadingAnchor),
      stack.trailingAnchor.constraint(equalTo: content.trailingAnchor),
      stack.topAnchor.constraint(equalTo: content.topAnchor),
      stack.bottomAnchor.constraint(equalTo: content.bottomAnchor),
    ])
    panel.contentView = content
    fit(keepTop: false)
  }

  private func label(_ text: String, font: NSFont = .systemFont(ofSize: 13), color: NSColor = .labelColor) -> NSTextField {
    let field = NSTextField(wrappingLabelWithString: text)
    field.font = font
    field.textColor = color
    field.isSelectable = true
    field.preferredMaxLayoutWidth = width
    field.translatesAutoresizingMaskIntoConstraints = false
    field.widthAnchor.constraint(equalToConstant: width).isActive = true
    return field
  }

  private func scriptView(_ tokens: [(String, String)]) -> NSView {
    let height: CGFloat = 340
    let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: width, height: height))
    scroll.hasVerticalScroller = true
    scroll.autohidesScrollers = false
    scroll.borderType = .bezelBorder
    let text = NSTextView(frame: NSRect(x: 0, y: 0, width: width, height: height))
    text.isEditable = false
    text.isSelectable = true
    text.isRichText = true
    text.allowsUndo = false
    text.minSize = NSSize(width: 0, height: 0)
    text.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
    text.isVerticallyResizable = true
    text.isHorizontallyResizable = false
    text.autoresizingMask = [.width]
    // Long lines wrap, so nothing can hide past the right edge.
    text.textContainer?.containerSize = NSSize(width: width, height: CGFloat.greatestFiniteMagnitude)
    text.textContainer?.widthTracksTextView = true
    text.textContainerInset = NSSize(width: 6, height: 6)
    text.textStorage?.setAttributedString(highlighted(tokens))
    scroll.documentView = text
    scroll.translatesAutoresizingMaskIntoConstraints = false
    scroll.widthAnchor.constraint(equalToConstant: width).isActive = true
    scroll.heightAnchor.constraint(equalToConstant: height).isActive = true
    return scroll
  }

  private func section(_ title: String, content: NSView) {
    let button = NSButton(title: "▸  " + title, target: self, action: #selector(toggle(_:)))
    button.isBordered = false
    button.font = .systemFont(ofSize: 13, weight: .semibold)
    button.contentTintColor = .linkColor
    button.tag = sections.count
    content.isHidden = true
    sections.append((button, content, title))
    stack.addArrangedSubview(button)
    stack.addArrangedSubview(content)
  }

  @objc private func toggle(_ sender: NSButton) {
    let section = sections[sender.tag]
    section.content.isHidden.toggle()
    section.button.title = (section.content.isHidden ? "▸  " : "▾  ") + section.title
    fit(keepTop: true)
  }

  /// Sizes the panel to its content; opening a section grows it downwards.
  private func fit(keepTop: Bool) {
    panel.contentView?.layoutSubtreeIfNeeded()
    let size = stack.fittingSize
    var frame = panel.frameRect(forContentRect: NSRect(origin: .zero, size: size))
    let old = panel.frame
    frame.origin = NSPoint(x: old.minX, y: keepTop ? old.maxY - frame.height : old.minY)
    panel.setFrame(frame, display: true)
  }

  @objc private func choose(_ sender: NSButton) { finish(sender.identifier?.rawValue ?? "deny") }

  private var done = false

  func finish(_ value: String) {
    // Only the first answer counts (a button, then the close it causes).
    guard !done else { return }
    done = true
    answer = value == "once" || value == "always" ? value : "deny"
    NSApp.stopModal()
    panel.orderOut(nil)
  }

  func windowWillClose(_ notification: Notification) { finish("deny") }

  func enableAllow() { allowButtons.forEach { $0.isEnabled = true } }
}

/// Deny is the default and the cancel action; closing, Escape or 3 minutes without an answer denies.
func ask(_ prompt: Prompt) -> String {
  let app = NSApplication.shared
  app.setActivationPolicy(.accessory)
  app.finishLaunching()
  let controller = AskController(prompt)
  let enable = Timer(timeInterval: 1.0, repeats: false) { _ in controller.enableAllow() }
  let giveUp = Timer(timeInterval: 180, repeats: false) { _ in controller.finish("deny") }
  RunLoop.main.add(enable, forMode: .common)
  RunLoop.main.add(giveUp, forMode: .common)
  controller.panel.center()
  app.activate(ignoringOtherApps: true)
  controller.panel.makeKeyAndOrderFront(nil)
  app.runModal(for: controller.panel)
  enable.invalidate()
  giveUp.invalidate()
  return controller.answer
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard let command = arguments.first else {
  fail("Usage: keyhop-auth create [--biometry-only] | derive <unlock|change|grant|bypass> | ask")
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

case "ask":
  print(ask(readPrompt()))

default:
  fail("Unknown command: \(command)")
}
