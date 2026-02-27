import Foundation
import Testing

@testable import SquirrelOpsHelper

@Suite("ServiceScanner")
struct ServiceScannerTests {

    let sampleNmapXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE nmaprun>
        <nmaprun>
            <host>
                <address addr="192.168.1.1" addrtype="ipv4"/>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service product="nginx" version="1.24"/>
                    </port>
                    <port protocol="tcp" portid="443">
                        <state state="open"/>
                        <service product="nginx" version="1.24"/>
                    </port>
                    <port protocol="tcp" portid="22">
                        <state state="closed"/>
                    </port>
                </ports>
            </host>
        </nmaprun>
        """

    @Test("Parse nmap XML with open ports")
    func parseOpenPorts() {
        let results = ServiceScanner.parseNmapXML(sampleNmapXML.data(using: .utf8)!)
        #expect(results.count == 2)
        #expect(results[0]["ip"] as? String == "192.168.1.1")
        #expect(results[0]["port"] as? Int == 80)
        #expect(results[0]["banner"] as? String == "nginx/1.24")
    }

    @Test("Parse nmap XML skips closed ports")
    func parseSkipsClosed() {
        let results = ServiceScanner.parseNmapXML(sampleNmapXML.data(using: .utf8)!)
        let portNums = results.compactMap { $0["port"] as? Int }
        #expect(!portNums.contains(22))
    }

    @Test("Parse nmap XML with no hosts returns empty")
    func parseEmptyHosts() {
        let xml = """
            <?xml version="1.0"?><nmaprun></nmaprun>
            """
        let results = ServiceScanner.parseNmapXML(xml.data(using: .utf8)!)
        #expect(results.isEmpty)
    }

    @Test("Parse nmap XML with no service banner")
    func parseNoBanner() {
        let xml = """
            <?xml version="1.0"?>
            <nmaprun>
                <host>
                    <address addr="10.0.0.1" addrtype="ipv4"/>
                    <ports>
                        <port protocol="tcp" portid="9090">
                            <state state="open"/>
                        </port>
                    </ports>
                </host>
            </nmaprun>
            """
        let results = ServiceScanner.parseNmapXML(xml.data(using: .utf8)!)
        #expect(results.count == 1)
        #expect(results[0]["banner"] == nil)
    }

    @Test("Parse empty data returns empty")
    func parseEmptyData() {
        let results = ServiceScanner.parseNmapXML(Data())
        #expect(results.isEmpty)
    }

    @Test("Scan with empty targets returns empty")
    func scanEmptyTargets() throws {
        let results = try ServiceScanner.scan(targets: [], ports: [80])
        #expect(results.isEmpty)
    }

    @Test("Scan with empty ports returns empty")
    func scanEmptyPorts() throws {
        let results = try ServiceScanner.scan(targets: ["192.168.1.1"], ports: [])
        #expect(results.isEmpty)
    }
}
