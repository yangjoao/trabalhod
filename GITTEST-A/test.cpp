Criptografia em Java: Simétrica, Assimétrica e Hash
Aqui está um exemplo completo de como implementar criptografia simétrica, assimétrica e funções hash em Java:

1. Criptografia Simétrica (AES)
java
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class CriptografiaSimetrica {
    
    public static void main(String[] args) throws Exception {
        // Gerar chave AES (256 bits)
        SecretKey chave = gerarChaveAES();
        
        // Texto original
        String texto = "Mensagem secreta para criptografar";
        System.out.println("Original: " + texto);
        
        // Criptografar
        byte[] iv = gerarIV();
        String textoCriptografado = criptografarAES(texto, chave, iv);
        System.out.println("Criptografado: " + textoCriptografado);
        
        // Descriptografar
        String textoDescriptografado = descriptografarAES(textoCriptografado, chave, iv);
        System.out.println("Descriptografado: " + textoDescriptografado);
    }
    
    public static SecretKey gerarChaveAES() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // Tamanho da chave
        return keyGenerator.generateKey();
    }
    
    public static byte[] gerarIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
    
    public static String criptografarAES(String texto, SecretKey chave, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, chave, new IvParameterSpec(iv));
        
        byte[] textoCriptografado = cipher.doFinal(texto.getBytes());
        return Base64.getEncoder().encodeToString(textoCriptografado);
    }
    
    public static String descriptografarAES(String textoCriptografado, SecretKey chave, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, chave, new IvParameterSpec(iv));
        
        byte[] textoDecodificado = Base64.getDecoder().decode(textoCriptografado);
        byte[] textoDescriptografado = cipher.doFinal(textoDecodificado);
        return new String(textoDescriptografado);
    }
}
2. Criptografia Assimétrica (RSA)
java
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CriptografiaAssimetrica {
    
    public static void main(String[] args) throws Exception {
        // Gerar par de chaves
        KeyPair parChaves = gerarParChavesRSA();
        PublicKey chavePublica = parChaves.getPublic();
        PrivateKey chavePrivada = parChaves.getPrivate();
        
        // Texto original
        String texto = "Mensagem secreta para criptografia RSA";
        System.out.println("Original: " + texto);
        
        // Criptografar com chave pública
        String textoCriptografado = criptografarRSA(texto, chavePublica);
        System.out.println("Criptografado: " + textoCriptografado);
        
        // Descriptografar com chave privada
        String textoDescriptografado = descriptografarRSA(textoCriptografado, chavePrivada);
        System.out.println("Descriptografado: " + textoDescriptografado);
    }
    
    public static KeyPair gerarParChavesRSA() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Tamanho da chave
        return keyPairGenerator.generateKeyPair();
    }
    
    public static String criptografarRSA(String texto, PublicKey chavePublica) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, chavePublica);
        
        byte[] textoCriptografado = cipher.doFinal(texto.getBytes());
        return Base64.getEncoder().encodeToString(textoCriptografado);
    }
    
    public static String descriptografarRSA(String textoCriptografado, PrivateKey chavePrivada) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, chavePrivada);
        
        byte[] textoDecodificado = Base64.getDecoder().decode(textoCriptografado);
        byte[] textoDescriptografado = cipher.doFinal(textoDecodificado);
        return new String(textoDescriptografado);
    }
    
    // Métodos para converter chaves para/de String (útil para armazenamento)
    public static String chavePublicaParaString(PublicKey chavePublica) {
        return Base64.getEncoder().encodeToString(chavePublica.getEncoded());
    }
    
    public static PublicKey stringParaChavePublica(String chavePublicaStr) throws Exception {
        byte[] bytesChave = Base64.getDecoder().decode(chavePublicaStr);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytesChave);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }
    
    public static String chavePrivadaParaString(PrivateKey chavePrivada) {
        return Base64.getEncoder().encodeToString(chavePrivada.getEncoded());
    }
    
    public static PrivateKey stringParaChavePrivada(String chavePrivadaStr) throws Exception {
        byte[] bytesChave = Base64.getDecoder().decode(chavePrivadaStr);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytesChave);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }
}
3. Funções Hash (SHA-256)
java
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class FuncoesHash {
    
    public static void main(String[] args) throws Exception {
        String texto = "Senha secreta para hashing";
        
        // Gerar hash SHA-256
        String hash = gerarHashSHA256(texto);
        System.out.println("Texto original: " + texto);
        System.out.println("Hash SHA-256: " + hash);
    }
    
    public static String gerarHashSHA256(String texto) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(texto.getBytes());
        
        // Converter bytes para representação hexadecimal
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        
        return hexString.toString();
        
        // Alternativa: retornar em Base64
        // return Base64.getEncoder().encodeToString(hashBytes);
    }
    
    // Exemplo com "salt" para maior segurança (usado em senhas)
    public static String gerarHashComSalt(String texto, String salt) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(salt.getBytes());
        byte[] hashBytes = digest.digest(texto.getBytes());
        
        return Base64.getEncoder().encodeToString(hashBytes);
    }
}
Considerações importantes:
Segurança:

Para AES, sempre use IV (vetor de inicialização) único para cada operação

Para RSA, use tamanhos de chave adequados (2048 bits ou mais)

Para hashes de senha, prefira algoritmos como PBKDF2, bcrypt ou scrypt

Gerenciamento de chaves:

Nunca armazene chaves hardcoded no código

Use sistemas seguros como KeyStore ou HSM para armazenar chaves

Algoritmos:

AES para simétrica

RSA para assimétrica

SHA-256 ou SHA-3 para hash (para senhas, use funções específicas como PBKDF2)

Exceções:

O código mostrado lança exceções para simplificação

Em produção, trate adequadamente todas as exceções

Estes exemplos fornecem uma base para implementação de criptografia em Java. Para uso em produção, considere consultar as melhores práticas de segurança atualizadas