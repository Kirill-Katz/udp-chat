import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/** Independent Java peer for the protocol in ../PROTOCOL.md. Requires Java 21. */
public final class Chat {
    static final String DEFAULT_GROUP = "239.255.42.99";
    static final int MAX_PACKET = 8192;
    static final SecureRandom RANDOM = new SecureRandom();
    static String id() { byte[] b = new byte[16]; RANDOM.nextBytes(b); return HexFormat.of().formatHex(b); }
    static boolean validId(String s) { return s != null && s.matches("[0-9a-f]{32}"); }
    static boolean validName(String s) {
        if (s == null || s.isEmpty() || s.getBytes(StandardCharsets.UTF_8).length > 32) return false;
        return s.codePoints().allMatch(c -> Character.isLetterOrDigit(c) || c == '_' || c == '-');
    }
    static boolean validText(String s) {
        return s != null && !s.isEmpty() && s.codePointCount(0, s.length()) <= 500
                && s.codePoints().noneMatch(c -> Character.getType(c) == Character.CONTROL);
    }
    static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    static String decodeUtf8(byte[] b) throws CharacterCodingException {
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString();
    }
    static byte[] key(String pass, String group, int port) throws Exception {
        var spec = new PBEKeySpec(pass.toCharArray(), utf8("lan-chat-v1|" + group + "|" + port), 600000, 256);
        try { return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded(); }
        finally { spec.clearPassword(); }
    }
    static byte[] aad(Packet p, String recipient) {
        return utf8(String.join("\0", "lan-chat-private-v1", p.peerId, p.name, p.to, recipient, p.messageId));
    }
    static void encrypt(Packet p, String recipient, String message, byte[] key) throws Exception {
        byte[] nonce = new byte[12]; RANDOM.nextBytes(nonce);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        c.updateAAD(aad(p, recipient));
        p.nonce = Base64.getEncoder().encodeToString(nonce);
        p.ciphertext = Base64.getEncoder().encodeToString(c.doFinal(utf8(message)));
    }
    static String decrypt(Packet p, String recipient, byte[] key) throws Exception {
        byte[] nonce = Base64.getDecoder().decode(p.nonce);
        byte[] ciphertext = Base64.getDecoder().decode(p.ciphertext);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        c.updateAAD(aad(p, recipient));
        String result = decodeUtf8(c.doFinal(ciphertext));
        if (!validText(result)) throw new IllegalArgumentException("invalid decrypted text");
        return result;
    }

    static final class Packet {
        String type, peerId, name, messageId, to, text, nonce, ciphertext;
        Packet(String type, String peerId, String name) {
            this.type = type; this.peerId = peerId; this.name = name; this.messageId = id();
        }
        String json() {
            StringBuilder b = new StringBuilder("{\"v\":1,\"type\":").append(Json.quote(type))
                    .append(",\"peer_id\":").append(Json.quote(peerId)).append(",\"name\":").append(Json.quote(name))
                    .append(",\"message_id\":").append(Json.quote(messageId));
            if (to != null) b.append(",\"to\":").append(Json.quote(to));
            if (text != null) b.append(",\"text\":").append(Json.quote(text));
            if (nonce != null) b.append(",\"nonce\":").append(Json.quote(nonce));
            if (ciphertext != null) b.append(",\"ciphertext\":").append(Json.quote(ciphertext));
            return b.append('}').toString();
        }
        static Packet parse(byte[] bytes) throws Exception {
            if (bytes.length > MAX_PACKET) throw new IllegalArgumentException("oversized datagram");
            Map<String,Object> m = Json.parse(decodeUtf8(bytes));
            if (!Integer.valueOf(1).equals(m.get("v"))) throw new IllegalArgumentException("version");
            String type = field(m, "type"), peer = field(m, "peer_id"), name = field(m, "name");
            String msg = field(m, "message_id");
            if (!validId(peer) || !validId(msg) || !validName(name)) throw new IllegalArgumentException("header");
            Set<String> allowed = new HashSet<>(List.of("v", "type", "peer_id", "name", "message_id"));
            Packet p = new Packet(type, peer, name); p.messageId = msg;
            switch (type) {
                case "claim", "announce", "heartbeat", "leave" -> { }
                case "hello", "conflict" -> { allowed.add("to"); p.to = field(m, "to"); if (!validId(p.to)) throw new IllegalArgumentException("recipient"); }
                case "general" -> { allowed.add("text"); p.text = field(m, "text"); if (!validText(p.text)) throw new IllegalArgumentException("text"); }
                case "private" -> {
                    allowed.addAll(List.of("to", "nonce", "ciphertext"));
                    p.to = field(m, "to"); p.nonce = field(m, "nonce"); p.ciphertext = field(m, "ciphertext");
                    byte[] n = Base64.getDecoder().decode(p.nonce), c = Base64.getDecoder().decode(p.ciphertext);
                    if (!validId(p.to) || n.length != 12 || c.length < 17 || c.length > 2016
                            || !Base64.getEncoder().encodeToString(n).equals(p.nonce)
                            || !Base64.getEncoder().encodeToString(c).equals(p.ciphertext)) throw new IllegalArgumentException("encrypted fields");
                }
                default -> throw new IllegalArgumentException("type");
            }
            if (!m.keySet().equals(allowed)) throw new IllegalArgumentException("missing or unexpected field");
            return p;
        }
        static String field(Map<String,Object> m, String k) {
            if (!(m.get(k) instanceof String s)) throw new IllegalArgumentException("field " + k);
            return s;
        }
    }

    /** Small strict JSON object parser; values in this protocol are strings or integer v. */
    static final class Json {
        final String s; int i;
        Json(String s) { this.s = s; }
        static String quote(String s) {
            StringBuilder b = new StringBuilder("\"");
            s.codePoints().forEach(c -> {
                if (c == '"' || c == '\\') b.append('\\').appendCodePoint(c);
                else if (c < 32) b.append(String.format("\\u%04x", c));
                else b.appendCodePoint(c);
            });
            return b.append('"').toString();
        }
        static Map<String,Object> parse(String s) {
            Json p = new Json(s); p.ws(); p.expect('{'); Map<String,Object> m = new HashMap<>(); p.ws();
            if (!p.take('}')) {
                do {
                    p.ws(); String k = p.string(); p.ws(); p.expect(':'); p.ws();
                    Object v = p.peek() == '"' ? p.string() : p.integer();
                    if (m.putIfAbsent(k, v) != null) throw new IllegalArgumentException("duplicate key");
                    p.ws(); if (p.take('}')) break; p.expect(',');
                } while (true);
            }
            p.ws(); if (p.i != s.length()) throw new IllegalArgumentException("trailing JSON");
            return m;
        }
        char peek() { if (i >= s.length()) throw new IllegalArgumentException("truncated JSON"); return s.charAt(i); }
        void ws() { while (i < s.length() && " \t\r\n".indexOf(s.charAt(i)) >= 0) i++; }
        boolean take(char c) { if (i < s.length() && s.charAt(i) == c) { i++; return true; } return false; }
        void expect(char c) { if (!take(c)) throw new IllegalArgumentException("expected " + c); }
        Integer integer() {
            int start = i; if (take('-')) { }
            if (!take('0')) { if (peek() < '1' || peek() > '9') throw new IllegalArgumentException("integer");
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++; }
            try { return Integer.valueOf(s.substring(start, i)); } catch (NumberFormatException e) { throw new IllegalArgumentException("integer", e); }
        }
        String string() {
            expect('"'); StringBuilder b = new StringBuilder();
            while (true) {
                char c = peek(); i++; if (c == '"') return b.toString();
                if (c < 32) throw new IllegalArgumentException("control in string");
                if (c != '\\') { if (Character.isSurrogate(c)) {
                        if (!Character.isHighSurrogate(c) || i >= s.length() || !Character.isLowSurrogate(s.charAt(i))) throw new IllegalArgumentException("surrogate");
                        b.append(c).append(s.charAt(i++));
                    } else b.append(c); continue; }
                c = peek(); i++;
                switch (c) {
                    case '"', '\\', '/' -> b.append(c);
                    case 'b' -> b.append('\b'); case 'f' -> b.append('\f'); case 'n' -> b.append('\n');
                    case 'r' -> b.append('\r'); case 't' -> b.append('\t');
                    case 'u' -> {
                        if (i + 4 > s.length()) throw new IllegalArgumentException("unicode escape");
                        char u;
                        try { u = (char) Integer.parseInt(s.substring(i, i + 4), 16); } catch (NumberFormatException e) { throw new IllegalArgumentException("unicode escape"); }
                        i += 4;
                        if (Character.isLowSurrogate(u)) throw new IllegalArgumentException("surrogate");
                        if (Character.isHighSurrogate(u)) {
                            expect('\\'); expect('u');
                            if (i + 4 > s.length()) throw new IllegalArgumentException("surrogate");
                            char low;
                            try { low = (char) Integer.parseInt(s.substring(i, i + 4), 16); } catch (NumberFormatException e) { throw new IllegalArgumentException("surrogate"); }
                            i += 4; if (!Character.isLowSurrogate(low)) throw new IllegalArgumentException("surrogate");
                            b.append(u).append(low);
                        } else b.append(u);
                    }
                    default -> throw new IllegalArgumentException("escape");
                }
            }
        }
    }

    record Member(String id, String name, InetSocketAddress address, long seen) { }
    final String name, peerId; final InetSocketAddress group; final byte[] key; final DatagramChannel shared, personal;
    final Selector selector; final PrintWriter log; final Map<String,Member> members = new HashMap<>();
    final Map<String,Long> seen = new HashMap<>(); final BlockingQueue<String> input = new LinkedBlockingQueue<>();
    boolean joined; long start, heartbeat;
    Chat(String name, int port, String groupText, String pass, String ifaceName, Path logPath) throws Exception {
        this.name = name; peerId = id(); group = new InetSocketAddress(InetAddress.getByName(groupText), port);
        key = key(pass, groupText, port);
        NetworkInterface iface = chooseInterface(ifaceName);
        shared = DatagramChannel.open(StandardProtocolFamily.INET);
        shared.setOption(StandardSocketOptions.SO_REUSEADDR, true);
        shared.bind(new InetSocketAddress("0.0.0.0", port));
        shared.join(group.getAddress(), iface);
        personal = DatagramChannel.open(StandardProtocolFamily.INET);
        personal.bind(new InetSocketAddress("0.0.0.0", 0));
        personal.setOption(StandardSocketOptions.IP_MULTICAST_IF, iface);
        personal.setOption(StandardSocketOptions.IP_MULTICAST_TTL, 1);
        personal.setOption(StandardSocketOptions.IP_MULTICAST_LOOP, true);
        shared.configureBlocking(false); personal.configureBlocking(false);
        selector = Selector.open(); shared.register(selector, SelectionKey.OP_READ); personal.register(selector, SelectionKey.OP_READ);
        log = new PrintWriter(Files.newBufferedWriter(logPath, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND), true);
        System.out.println("* checking name " + name + " via " + iface.getName() + "; private port " + ((InetSocketAddress)personal.getLocalAddress()).getPort());
    }
    static NetworkInterface chooseInterface(String requested) throws Exception {
        for (NetworkInterface n : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (requested != null && !requested.equals(n.getName())) continue;
            if (n.isUp() && (requested != null || (!n.isLoopback() && n.supportsMulticast()))
                    && Collections.list(n.getInetAddresses()).stream().anyMatch(a -> a instanceof Inet4Address)) return n;
        }
        throw new IllegalArgumentException("no usable IPv4 multicast interface; specify -interface");
    }
    void record(String action, SocketAddress endpoint, String kind, int size, String reason) {
        log.printf("%s action=%s endpoint=%s kind=%s size=%d reason=%s%n", Instant.now(), action, endpoint, kind, size, reason);
    }
    Packet packet(String type) { return new Packet(type, peerId, name); }
    void send(Packet p, SocketAddress dest) throws Exception {
        byte[] bytes = utf8(p.json()); if (bytes.length > MAX_PACKET) throw new IllegalArgumentException("oversized outgoing packet");
        try { personal.send(ByteBuffer.wrap(bytes), dest); record("send", dest, p.type, bytes.length, ""); }
        catch (Exception e) { record("drop", dest, p.type, bytes.length, e.toString()); throw e; }
    }
    void control(String type, String to, SocketAddress dest) throws Exception { Packet p = packet(type); p.to = to; send(p, dest); }
    void drop(Packet p, SocketAddress addr, int size, String reason) { record("drop", addr, p.type, size, reason); }
    Member byName(String n) { for (Member m : members.values()) if (m.name.equals(n)) return m; return null; }
    void remember(Packet p, InetSocketAddress addr, long now) {
        Member existing = members.get(p.peerId);
        if (existing != null) {
            if (!existing.name.equals(p.name) || !existing.address.equals(addr)) throw new IllegalArgumentException("identity or endpoint changed");
        } else {
            Member same = byName(p.name);
            if (same != null && same.id.compareTo(p.peerId) < 0) throw new IllegalArgumentException("duplicate name");
            if (same != null) remove(same);
            if (members.size() >= 1024) throw new IllegalArgumentException("member table full");
            System.out.println("* " + p.name + " joined the chat");
        }
        members.put(p.peerId, new Member(p.peerId, p.name, addr, now));
    }
    void remove(Member m) { members.remove(m.id); System.out.println("* " + m.name + " left the chat"); }
    boolean duplicate(Packet p, long now) {
        String k = p.peerId + p.messageId;
        Long old = seen.get(k); if (old != null && now - old < 60000) return true;
        if (seen.size() >= 4096) seen.entrySet().stream().min(Map.Entry.comparingByValue()).ifPresent(e -> seen.remove(e.getKey()));
        seen.put(k, now); return false;
    }
    void receive(Packet p, InetSocketAddress addr, boolean onShared, int size, long now) throws Exception {
        boolean groupType = List.of("claim", "announce", "heartbeat", "general", "leave").contains(p.type);
        if (groupType != onShared || (p.to != null && !p.to.equals(peerId))) { drop(p, addr, size, "wrong socket or recipient"); return; }
        if (p.peerId.equals(peerId)) {
            if (joined && p.type.equals("general") && !duplicate(p, now)) System.out.println("[general] " + name + ": " + p.text);
            return;
        }
        if (p.name.equals(name)) {
            if (p.type.equals("claim")) {
                if (joined || peerId.compareTo(p.peerId) < 0) control("conflict", p.peerId, addr);
                else throw new IllegalStateException("name is already in use");
            } else if (p.type.equals("conflict")) {
                if (!joined || p.peerId.compareTo(peerId) < 0) throw new IllegalStateException("name is already in use");
            } else if (List.of("hello", "announce", "heartbeat", "general").contains(p.type)) {
                if (!joined || p.peerId.compareTo(peerId) < 0) throw new IllegalStateException("name is already in use");
                control("conflict", p.peerId, addr);
            }
            return;
        }
        if (p.type.equals("conflict")) { drop(p, addr, size, "other name"); return; }
        if (p.type.equals("claim")) { if (joined) control("hello", p.peerId, addr); return; }
        if (p.type.equals("leave")) {
            Member m = members.get(p.peerId);
            if (m != null && m.name.equals(p.name) && m.address.equals(addr) && !duplicate(p, now)) remove(m);
            else drop(p, addr, size, "unknown leave");
            return;
        }
        String plaintext = null;
        try {
            if (p.type.equals("private")) {
                if (!joined) throw new IllegalArgumentException("not joined");
                plaintext = decrypt(p, name, key);
            }
            Member m = members.get(p.peerId);
            if (m != null && (!m.name.equals(p.name) || !m.address.equals(addr))) throw new IllegalArgumentException("identity or endpoint changed");
            if (duplicate(p, now)) throw new IllegalArgumentException("duplicate");
            remember(p, addr, now);
            if (p.type.equals("general")) System.out.println("[general] " + p.name + ": " + p.text);
            if (p.type.equals("private")) System.out.println("[private] " + p.name + ": " + plaintext);
        } catch (Exception e) { drop(p, addr, size, e.toString()); }
    }
    void read(DatagramChannel channel, boolean onShared) throws Exception {
        ByteBuffer b = ByteBuffer.allocate(65535); SocketAddress source = channel.receive(b); if (source == null) return;
        byte[] bytes = Arrays.copyOf(b.array(), b.position()); Packet p;
        try { p = Packet.parse(bytes); record("receive", source, p.type, bytes.length, ""); }
        catch (Exception e) { record("receive", source, "invalid", bytes.length, ""); record("drop", source, "invalid", bytes.length, e.toString()); return; }
        receive(p, (InetSocketAddress) source, onShared, bytes.length, System.currentTimeMillis());
    }
    boolean command(String line) throws Exception {
        if (line.equals("/quit")) return true;
        if (!joined) { System.out.println("! still checking name"); return false; }
        if (line.equals("/users")) {
            System.out.println(name + " (you)"); members.values().stream().sorted(Comparator.comparing(Member::name))
                    .forEach(m -> System.out.println(m.name + " " + m.address)); return false;
        }
        if (line.startsWith("/msg ")) {
            String rest = line.substring(5).stripLeading(); int split = rest.indexOf(' ');
            if (split < 1 || !validText(rest.substring(split + 1))) throw new IllegalArgumentException("usage: /msg name text");
            String targetName = rest.substring(0, split), text = rest.substring(split + 1);
            Member target = byName(targetName);
            if (target == null || targetName.equals(name)) throw new IllegalArgumentException(targetName + " is not online");
            Packet p = packet("private"); p.to = target.id; encrypt(p, target.name, text, key); send(p, target.address);
            System.out.println("[private -> " + targetName + ", sent without delivery guarantee] " + name + ": " + text);
        } else if (line.startsWith("/")) throw new IllegalArgumentException("commands: /msg name text, /users, /quit");
        else { if (!validText(line)) throw new IllegalArgumentException("message must contain 1-500 characters without controls");
            Packet p = packet("general"); p.text = line; send(p, group); }
        return false;
    }
    void run() throws Exception {
        Thread console = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
                String line; while ((line = r.readLine()) != null) input.put(line);
            } catch (Exception ignored) { } finally { input.offer("/quit"); }
        }, "console"); console.setDaemon(true); console.start();
        start = System.currentTimeMillis(); long nextClaim = start; boolean quitting = false;
        try {
            while (!quitting) {
                long now = System.currentTimeMillis();
                if (!joined && now - start >= 900) { joined = true; control("announce", null, group);
                    System.out.println("* ready as " + name + "; text, /msg name text, /users, /quit"); heartbeat = now; }
                if (!joined && now >= nextClaim) { control("claim", null, group); nextClaim = now + 250; }
                if (joined && now - heartbeat >= 5000) { control("heartbeat", null, group); heartbeat = now; }
                for (Member m : List.copyOf(members.values())) if (now - m.seen >= 15000) remove(m);
                seen.entrySet().removeIf(e -> now - e.getValue() >= 60000);
                String line; while ((line = input.poll()) != null) {
                    try { if (command(line)) { quitting = true; break; } }
                    catch (Exception e) { System.out.println("! " + e.getMessage()); }
                }
                if (quitting) break;
                selector.select(100);
                for (SelectionKey selected : selector.selectedKeys()) {
                    try { read((DatagramChannel) selected.channel(), selected.channel() == shared); }
                    catch (PortUnreachableException ignored) { }
                }
                selector.selectedKeys().clear();
            }
        } finally {
            if (joined) try { control("leave", null, group); } catch (Exception ignored) { }
            selector.close(); shared.close(); personal.close(); log.close();
        }
    }
    public static void main(String[] args) {
        try {
            Map<String,String> options = new HashMap<>();
            for (int i = 0; i < args.length; i += 2) {
                if (i + 1 == args.length || !Set.of("-name", "-port", "-group", "-passphrase", "-interface", "-log").contains(args[i])
                        || options.putIfAbsent(args[i], args[i + 1]) != null) throw new IllegalArgumentException("usage: java Chat -name NAME -passphrase PASS [-port 9000] [-group 239.255.42.99] [-interface NAME] [-log FILE]");
            }
            String name = options.get("-name"), pass = options.get("-passphrase");
            if (!validName(name) || pass == null || pass.isEmpty()) throw new IllegalArgumentException("valid -name and -passphrase required");
            int port = Integer.parseInt(options.getOrDefault("-port", "9000")); if (port < 1 || port > 65535) throw new IllegalArgumentException("port");
            String group = InetAddress.getByName(options.getOrDefault("-group", DEFAULT_GROUP)).getHostAddress();
            if (!(InetAddress.getByName(group) instanceof Inet4Address address) || !address.isMulticastAddress()) throw new IllegalArgumentException("IPv4 multicast group required");
            Path log = Path.of(options.getOrDefault("-log", "peer-" + name + ".log"));
            new Chat(name, port, group, pass, options.get("-interface"), log).run();
        } catch (Exception e) { System.err.println(e.getMessage()); System.exit(1); }
    }
}
