import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import com.fasterxml.jackson.databind.ObjectMapper;

public class DigitalSignatureExample {

    // Caminhos para os arquivos de chave privada e pública
    private static final String PRIVATE_KEY_PATH = "private_key.pem";
    private static final String PUBLIC_KEY_PATH = "public_key_teste.pem";

    // Dados que serão assinados
    private static final String BODY_DATA_JSON = "{ \"transaction\": { \"key\": \"11111111111\", \"amount\": 2.11, \"callback_url\": \"https://enu74s7tvngo.x.pipedream.net/\", \"external_id\": \"12312312\", \"pixType\": \"CPF\" } }";

    public static void main(String[] args) {
        try {
            String privateKeyPem = new String(Files.readAllBytes(Paths.get(PRIVATE_KEY_PATH)));
            String publicKeyPem = new String(Files.readAllBytes(Paths.get(PUBLIC_KEY_PATH)));

            PrivateKey privateKey = getPrivateKeyFromPem(privateKeyPem);
            PublicKey publicKey = getPublicKeyFromPem(publicKeyPem);

            String signature = signData(BODY_DATA_JSON, privateKey);
            boolean isValid = verifySignature(BODY_DATA_JSON, signature, publicKey);

            System.out.println("Signature: " + signature);
            System.out.println("Is valid: " + isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Função para assinar dados usando uma chave privada
    public static String signData(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        byte[] signedData = signature.sign();
        return Base64.getEncoder().encodeToString(signedData);
    }

    // Função para verificar a assinatura usando uma chave pública
    public static boolean verifySignature(String data, String signatureStr, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data.getBytes());
        byte[] signedData = Base64.getDecoder().decode(signatureStr);
        return signature.verify(signedData);
    }

    // Função para obter a chave privada a partir de um arquivo PEM
    public static PrivateKey getPrivateKeyFromPem(String pem) throws Exception {
        String privateKeyPem = pem.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replaceAll("\\s+", "");
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyPem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    // Função para obter a chave pública a partir de um arquivo PEM
    public static PublicKey getPublicKeyFromPem(String pem) throws Exception {
        String publicKeyPem = pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\\s+", "");
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyPem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
}