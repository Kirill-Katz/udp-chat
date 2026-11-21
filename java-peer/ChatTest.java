import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;

public final class ChatTest {
    static void check(boolean yes, String reason) { if (!yes) throw new AssertionError(reason); }
    public static void main(String[] args) throws Exception {
        byte[] key = Chat.key("correct horse battery staple", Chat.DEFAULT_GROUP, 9000);
        check(HexFormat.of().formatHex(key).equals("c37b2a13646807667bf8fc9a232df3c0044a5f47e3b8b47b39238d16e2512fa0"), "KDF vector");
        Chat.Packet p = new Chat.Packet("private", "00000000000000000000000000000001", "Ana");
        p.messageId = "10000000000000000000000000000001";
        p.to = "00000000000000000000000000000002";
        p.nonce = "AAECAwQFBgcICQoL";
        p.ciphertext = "NWmjMQ7kkUzwSB2AhLYb1I+q8deJM1uwIRaXoQ==";
        check(Chat.decrypt(p, "Ion", key).equals("hello 世界"), "AES-GCM Go vector");
        Chat.Packet decoded = Chat.Packet.parse(p.json().getBytes(StandardCharsets.UTF_8));
        check(Chat.decrypt(decoded, "Ion", key).equals("hello 世界"), "JSON round trip");
        Chat.Packet outbound = new Chat.Packet("private", p.to, "Ion"); outbound.to = p.peerId;
        Chat.encrypt(outbound, "Ana", "Java to Go 🚀", key);
        check(Chat.decrypt(Chat.Packet.parse(outbound.json().getBytes(StandardCharsets.UTF_8)), "Ana", key).equals("Java to Go 🚀"), "encrypted round trip");
        String base = "{\"v\":1,\"type\":\"general\",\"peer_id\":\"" + p.peerId + "\",\"name\":\"Ana\",\"message_id\":\"" + p.messageId + "\",\"text\":\"hello\"}";
        for (String bad : new String[] {base.replace("\"v\":1", "\"v\":1.0"), base.replace("\"text\":\"hello\"", "\"text\":\"hello\",\"text\":\"again\""), base.replace("hello", "\\ud800"), base + " {}"}) {
            try { Chat.Packet.parse(bad.getBytes(StandardCharsets.UTF_8)); throw new AssertionError("accepted invalid JSON"); }
            catch (IllegalArgumentException expected) { }
        }
        check(Chat.validText("🚀".repeat(500)), "Unicode code points");
        check(!Chat.validText("🚀".repeat(501)), "text bound");
        System.out.println("ChatTest passed");
    }
}
