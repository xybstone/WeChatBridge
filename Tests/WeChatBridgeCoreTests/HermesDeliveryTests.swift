import WeChatBridgeCore
import CryptoKit
import Darwin
import Foundation
import XCTest

final class HermesDeliveryTests: XCTestCase {
    private let secret = Data("route-secret".utf8)

    private func makeEvent(chatName: String? = "项目群") -> HermesDelivery.Event {
        HermesDelivery.Event(
            batchID: UUID(),
            createdAt: Date(timeIntervalSince1970: 1_790_000_000),
            chatName: chatName,
            archivePath: "/tmp/inbox/Ready/ABC/聊天记录.zip",
            archiveBytes: 1234
        )
    }

    // MARK: - URL validation

    func testLoopbackURLsAreAccepted() throws {
        for string in [
            "http://127.0.0.1:8644/webhooks/wechat",
            "http://localhost:8644/webhooks/wechat",
            "http://[::1]:8644/webhooks/wechat",
        ] {
            guard case .success(let url) = HermesDelivery.validatedURL(string) else {
                return XCTFail("expected \(string) to validate")
            }
            XCTAssertTrue(HermesDelivery.isLoopback(url))
        }
    }

    func testNonLoopbackURLsAreRefused() {
        for string in [
            "http://192.168.1.5:8644/webhooks/wechat",
            "https://example.com/webhooks/wechat",
            "http://0.0.0.0:8644/webhooks/wechat",
        ] {
            guard case .failure(let failure) = HermesDelivery.validatedURL(string) else {
                return XCTFail("expected \(string) to be refused")
            }
            XCTAssertEqual(failure, .notLoopback, string)
        }
    }

    func testEmptyAndMalformedURLsAreTheirOwnFailures() {
        if case .success = HermesDelivery.validatedURL(nil) { XCTFail("nil must not validate") }
        if case .success = HermesDelivery.validatedURL("  ") { XCTFail("blank must not validate") }
        guard case .failure(let failure) = HermesDelivery.validatedURL("not a url") else {
            return XCTFail("expected invalid")
        }
        XCTAssertEqual(failure, .invalidURL)
    }

    // MARK: - Event payload

    func testEventCarriesBatchPathAndUntrustedWrapper() throws {
        let event = makeEvent()
        XCTAssertEqual(event.eventType, "wechat.archive.shared")
        XCTAssertEqual(event.chatName, "项目群")
        XCTAssertTrue(event.archivePath.hasSuffix(".zip"))
        // The wrapper is the security property: the prompt must state that
        // archive content is untrusted and must not be obeyed.
        XCTAssertTrue(event.prompt.contains("不可信"))
    }

    func testEventEncodesStableJSONFields() throws {
        let event = makeEvent(chatName: nil)
        let data = try HermesDelivery.Event.encoder().encode(event)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(json["event_type"] as? String, "wechat.archive.shared")
        XCTAssertNotNil(json["batch_id"])
        XCTAssertNotNil(json["created_at"])
        XCTAssertNil(json["chat_name"])
        XCTAssertNotNil(json["archive_path"])
        XCTAssertEqual(json["archive_bytes"] as? Int, 1234)
        XCTAssertNotNil(json["prompt"])
    }

    // MARK: - Signature

    /// The signed content must be exactly `"<timestamp>.<body>"` — Hermes'
    /// generic V2 scheme — with a plain hex HMAC-SHA256, and the timestamp
    /// in whole seconds.
    func testSignatureMatchesHermesGenericV2Scheme() throws {
        let event = makeEvent()
        let url = try XCTUnwrap(URL(string: "http://127.0.0.1:8644/webhooks/wechat"))
        let now = Date(timeIntervalSince1970: 1_790_000_123)
        let request = try HermesDelivery.request(for: event, to: url, secret: secret, now: now)

        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
        XCTAssertEqual(request.value(forHTTPHeaderField: "X-GitHub-Event"), "wechat.archive.shared")
        let timestamp = try XCTUnwrap(request.value(forHTTPHeaderField: "X-Webhook-Timestamp"))
        XCTAssertEqual(timestamp, "1790000123")

        let body = try XCTUnwrap(request.httpBody)
        let signed = Data(timestamp.utf8) + Data(".".utf8) + body
        let expected = HMAC<SHA256>.authenticationCode(for: signed, using: SymmetricKey(data: secret))
            .map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(request.value(forHTTPHeaderField: "X-Webhook-Signature-V2"), expected)
        // A different secret must produce a different signature, or the
        // signature carries no authentication at all.
        let wrongKey = SymmetricKey(data: Data("other".utf8))
        let wrong = HMAC<SHA256>.authenticationCode(for: signed, using: wrongKey)
            .map { String(format: "%02x", $0) }.joined()
        XCTAssertNotEqual(request.value(forHTTPHeaderField: "X-Webhook-Signature-V2"), wrong)
    }

    // MARK: - Delivery outcomes

    func testDeliverAccepts2xx() async throws {
        let event = makeEvent()
        let url = try XCTUnwrap(URL(string: "http://127.0.0.1:1/webhooks/wechat"))
        let (status, _) = try await HermesDelivery.deliver(event, to: url, secret: secret) { _ in
            (200, Data("{\"status\":\"accepted\"}".utf8))
        }
        XCTAssertEqual(status, 200)
    }

    func testDeliverThrowsRejectedOnNon2xx() async throws {
        let event = makeEvent()
        let url = try XCTUnwrap(URL(string: "http://127.0.0.1:1/webhooks/wechat"))
        do {
            _ = try await HermesDelivery.deliver(event, to: url, secret: secret) { _ in
                (401, Data("signature mismatch".utf8))
            }
            XCTFail("expected a rejection")
        } catch let error as HermesDelivery.Failure {
            guard case .rejected(let status, _) = error else {
                return XCTFail("expected .rejected, got \(error)")
            }
            XCTAssertEqual(status, 401)
        }
    }

    // MARK: - Local HTTP round trip

    /// A real socket on 127.0.0.1: the request HermesDelivery builds must be
    /// POSTable and the body must arrive signed exactly as the receiving side
    /// recomputes it. This is the fixture-archive-to-real-webhook check the
    /// acceptance criteria ask for, at the smallest honest scale.
    func testSignedRequestPassesAServerSideV2Check() async throws {
        let recorder = try WebhookRecorder()
        try recorder.start()
        defer { recorder.stop() }

        let event = makeEvent()
        _ = try await HermesDelivery.deliver(event, to: recorder.url, secret: secret)
        let received = try await recorder.received()

        XCTAssertEqual(received.method, "POST")
        XCTAssertEqual(received.eventHeader, "wechat.archive.shared")
        let signed = Data(received.timestamp.utf8) + Data(".".utf8) + received.body
        let expected = HMAC<SHA256>.authenticationCode(for: signed, using: SymmetricKey(data: secret))
            .map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(received.signature, expected, "the server-side recomputation must match")

        let decoded = try JSONSerialization.jsonObject(with: received.body) as? [String: Any]
        XCTAssertEqual(decoded?["event_type"] as? String, "wechat.archive.shared")
    }
}

/// Minimal loopback HTTP server capturing one request, verified the way
/// Hermes' `_validate_signature` verifies it.
private final class WebhookRecorder {
    struct Received: Sendable {
        let method: String
        let eventHeader: String?
        let timestamp: String
        let signature: String?
        let body: Data
    }

    private static let queue = DispatchQueue(label: "hermes-delivery-tests")
    private var serverFD: Int32 = -1
    private var receivedBox = LockedBox<Received?>(nil)
    let url: URL

    init() throws {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw NSError(domain: "socket", code: Int(errno)) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = INADDR_LOOPBACK.bigEndian
        addr.sin_port = 0
        let bound = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        var boundAddr = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &boundAddr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                _ = getsockname(fd, $0, &length)
            }
        }
        guard bound == 0, listen(fd, 1) == 0 else {
            close(fd)
            throw NSError(domain: "bind", code: Int(errno))
        }
        serverFD = fd
        let port = boundAddr.sin_port.bigEndian
        url = URL(string: "http://127.0.0.1:\(port)/webhooks/wechat")!
    }

    func start() throws {
        let fd = serverFD
        guard fd >= 0 else { throw NSError(domain: "start", code: 1) }
        Self.queue.async { [receivedBox] in
            let client = accept(fd, nil, nil)
            guard client >= 0 else { return }
            defer { close(client) }
            var buffer = Data()
            var chunk = [UInt8](repeating: 0, count: 65_536)
            while true {
                let read = recv(client, &chunk, chunk.count, 0)
                guard read > 0 else { break }
                buffer.append(contentsOf: chunk[0..<read])
                if let headerEnd = buffer.range(of: Data("\r\n\r\n".utf8)) {
                    let head = String(decoding: buffer[..<headerEnd.lowerBound], as: UTF8.self)
                    let contentLength = head
                        .split(whereSeparator: \.isNewline)
                        .compactMap { line -> Int? in
                            guard line.lowercased().hasPrefix("content-length:") else { return nil }
                            return Int(line.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces))
                        }
                        .first ?? 0
                    if buffer.count - headerEnd.upperBound >= contentLength { break }
                }
            }
            let headerText = String(decoding: buffer, as: UTF8.self)
                .components(separatedBy: "\r\n\r\n").first ?? ""

            func header(_ name: String) -> String? {
                headerText.split(whereSeparator: \.isNewline)
                    .first { $0.lowercased().hasPrefix("\(name.lowercased()):") }?
                    .dropFirst(name.count + 1)
                    .trimmingCharacters(in: .whitespaces)
            }

            let body = buffer.range(of: Data("\r\n\r\n".utf8)).map { buffer[$0.upperBound...] } ?? Data()
            let method = headerText.split(separator: " ").first.map(String.init) ?? ""
            receivedBox.store(Received(
                method: method,
                eventHeader: header("X-GitHub-Event"),
                timestamp: header("X-Webhook-Timestamp") ?? "",
                signature: header("X-Webhook-Signature-V2"),
                body: Data(body)
            ))
            let response = Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".utf8)
            _ = response.withUnsafeBytes { pointer in
                send(client, pointer.baseAddress, pointer.count, 0)
            }
        }
    }

    func received() async throws -> Received {
        for _ in 0..<100 {
            if let received = receivedBox.load() { return received }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        throw NSError(domain: "recorder", code: 2, userInfo: [
            NSLocalizedDescriptionKey: "no request arrived within 5 s",
        ])
    }

    func stop() {
        if serverFD >= 0 {
            close(serverFD)
            serverFD = -1
        }
    }
}

private final class LockedBox<Value> {
    private var value: Value
    private let lock = NSLock()

    init(_ value: Value) {
        self.value = value
    }

    func load() -> Value {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func store(_ newValue: Value) {
        lock.lock()
        value = newValue
        lock.unlock()
    }
}
