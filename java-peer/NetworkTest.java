import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.file.*;

/** Socket smoke test; use an actual LAN interface. */
public final class NetworkTest {
    public static void main(String[] args) throws Exception {
        Chat a = new Chat("Ana", 39471, Chat.DEFAULT_GROUP, "test-passphrase", null, Path.of("peer-network-ana.log"));
        Chat b = new Chat("Ion", 39471, Chat.DEFAULT_GROUP, "test-passphrase", null, Path.of("peer-network-ion.log"));
        try {
            Chat.Packet general = a.packet("general"); general.text = "hello from Java";
            a.send(general, a.group);
            long until = System.currentTimeMillis() + 2500;
            boolean received = false;
            while (System.currentTimeMillis() < until) {
                ByteBuffer buffer = ByteBuffer.allocate(65535);
                if (b.shared.receive(buffer) != null) {
                    Chat.Packet p = Chat.Packet.parse(java.util.Arrays.copyOf(buffer.array(), buffer.position()));
                    if (p.type.equals("general") && p.text.equals(general.text)) { received = true; break; }
                }
                Thread.sleep(10);
            }
            if (!received) throw new AssertionError("multicast delivery failed");
            Chat.Packet privatePacket = a.packet("private"); privatePacket.to = b.peerId;
            Chat.encrypt(privatePacket, b.name, "private from Java", a.key);
            int bPort = ((InetSocketAddress) b.personal.getLocalAddress()).getPort();
            a.send(privatePacket, new InetSocketAddress(InetAddress.getLoopbackAddress(), bPort));
            until = System.currentTimeMillis() + 2500; received = false;
            while (System.currentTimeMillis() < until) {
                ByteBuffer buffer = ByteBuffer.allocate(65535);
                if (b.personal.receive(buffer) != null) {
                    Chat.Packet p = Chat.Packet.parse(java.util.Arrays.copyOf(buffer.array(), buffer.position()));
                    if (Chat.decrypt(p, b.name, b.key).equals("private from Java")) { received = true; break; }
                }
                Thread.sleep(10);
            }
            if (!received) throw new AssertionError("private delivery failed");
            System.out.println("NetworkTest passed");
        } finally {
            a.selector.close(); a.shared.close(); a.personal.close(); a.log.close();
            b.selector.close(); b.shared.close(); b.personal.close(); b.log.close();
        }
    }
}
