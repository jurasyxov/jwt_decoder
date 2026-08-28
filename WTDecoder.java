// JWTDecoder.java
import java.util.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.Base64;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class JWTDecoder {
    private String token;
    private String key;
    private JsonObject header;
    private JsonObject payload;
    private String signature;
    private Boolean validSignature;
    private Boolean expired;

    public JWTDecoder(String token, String key) {
        this.token = token;
        this.key = key;
    }

    public void decode() throws Exception {
        String[] parts = token.split("\\.");
        if (parts.length != 3) throw new IllegalArgumentException("Invalid JWT format");

        // Decode header
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
        header = JsonParser.parseString(headerJson).getAsJsonObject();

        // Decode payload
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
        payload = JsonParser.parseString(payloadJson).getAsJsonObject();

        signature = parts[2];

        // Check exp
        if (payload.has("exp")) {
            long exp = payload.get("exp").getAsLong();
            expired = Instant.now().getEpochSecond() > exp;
        }

        // Verify signature if key provided
        if (key != null && !key.isEmpty()) {
            validSignature = verifySignature(parts);
        }
    }

    private boolean verifySignature(String[] parts) throws Exception {
        String data = parts[0] + "." + parts[1];
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        mac.init(secretKey);
        byte[] sigBytes = mac.doFinal(data.getBytes());
        String sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes);
        return sigB64.equals(parts[2]);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("header", header);
        map.put("payload", payload);
        map.put("signature", signature);
        map.put("token", token);
        if (validSignature != null) map.put("valid_signature", validSignature);
        if (expired != null) map.put("expired", expired);
        return map;
    }

    public void print(boolean color) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        System.out.println("Header:");
        System.out.println(gson.toJson(header));
        System.out.println("Payload:");
        System.out.println(gson.toJson(payload));
        if (expired != null) {
            System.out.println("  Token " + (expired ? "expired" : "valid"));
        }
        if (validSignature != null) {
            System.out.println("  Signature " + (validSignature ? "verified" : "invalid"));
        }
        System.out.println("Signature: " + signature);
    }

    public static void main(String[] args) throws Exception {
        String token = null;
        String key = null;
        String file = null;
        boolean jsonOut = false;
        boolean color = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--key": key = args[++i]; break;
                case "--file": file = args[++i]; break;
                case "--json": jsonOut = true; break;
                case "--color": color = true; break;
                default: if (token == null) token = args[i];
            }
        }

        if (file != null) {
            token = new String(Files.readAllBytes(Paths.get(file))).trim();
        }
        if (token == null) {
            // try stdin
            if (System.console() == null) {
                token = new Scanner(System.in).nextLine().trim();
            } else {
                System.err.println("Error: no token provided");
                System.exit(1);
            }
        }

        JWTDecoder decoder = new JWTDecoder(token, key);
        decoder.decode();

        if (jsonOut) {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            System.out.println(gson.toJson(decoder.toMap()));
        } else {
            decoder.print(color || System.console() != null);
        }
    }
}
