package com.example.insecureapp;

import android.content.Context;
import android.content.SharedPreferences;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.net.*;
import javax.net.ssl.*;

/**
 * FICHIER DE TEST — contient intentionnellement des vulnérabilités crypto
 * Utilisez ce fichier pour tester CryptoLint AI
 */
public class InsecureCryptoExample {

    // ❌ Clé hardcodée dans le code source
    private static final String SECRET_KEY = "mysupersecretkey";
    private static final byte[] STATIC_IV = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // ❌ MD5 pour hachage de mot de passe
    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return bytesToHex(hash);
    }

    // ❌ SHA-1 pour signature de données
    public String signData(String data) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        sha.update(data.getBytes());
        return bytesToHex(sha.digest());
    }

    // ❌ AES sans mode (ECB par défaut)
    public byte[] encryptECB(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(plaintext.getBytes());
    }

    // ❌ AES-CBC sans authentification
    public byte[] encryptCBC(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[]{0x01, 0x02, 0x03, 0x04,
                                                                  0x05, 0x06, 0x07, 0x08,
                                                                  0x09, 0x0a, 0x0b, 0x0c,
                                                                  0x0d, 0x0e, 0x0f, 0x10});
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(plaintext.getBytes());
    }

    // ❌ DES obsolète
    public byte[] encryptDES(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec("weakkey".getBytes(), "DES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(plaintext.getBytes());
    }

    // ❌ RNG non cryptographique
    public String generateToken() {
        Random rng = new Random();
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            token.append((char) ('a' + rng.nextInt(26)));
        }
        return token.toString();
    }

    // ❌ Math.random() pour usage crypto
    public int generateOTP() {
        return (int) (Math.random() * 1000000);
    }

    // ❌ Clé stockée en SharedPreferences
    public void storeApiSecret(Context ctx, String secret) {
        SharedPreferences prefs = ctx.getSharedPreferences("app_prefs", Context.MODE_PRIVATE);
        prefs.edit().putString("api_key", secret).apply();
        prefs.edit().putString("crypto_password", "hardcoded123").apply();
    }

    // ❌ TLS hostname verification désactivé
    public HttpsURLConnection getInsecureConnection(String url) throws Exception {
        URL u = new URL(url);
        HttpsURLConnection conn = (HttpsURLConnection) u.openConnection();
        conn.setHostnameVerifier(HttpsURLConnection.ALLOW_ALL_HOSTNAME_VERIFIER);
        return conn;
    }

    // ❌ TrustManager qui accepte tout
    public SSLContext getTrustAllContext() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
            }
        };
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new SecureRandom());
        return sc;
    }

    // ❌ URL HTTP en clair
    public void fetchData() throws Exception {
        URL url = new URL("http://api.example.com/sensitive-data");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        // données transmises en clair
    }

    // ❌ Clé RSA trop petite
    public KeyPair generateWeakRSAKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);  // trop petit !
        return kpg.generateKeyPair();
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
