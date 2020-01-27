package oauth2.auth.service;

import oauth2.exception.OAuth2Exception;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

@Component
public class CertificateService {

    private static final String CERTIFICATE_ALIAS = "jwtcert";
    private static final String CERTIFICATE_ALGORITHM = "RSA";
    private static final String CERTIFICATE_DN = "CN=cn, O=o, L=L, ST=il, C= c";
    private static final String CERTIFICATE_NAME = "src/main/resources/data/keystore.jks";
    private static final int CERTIFICATE_BITS = 1024;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Value("${jwt.secret}")
    private String secret;

    @Autowired
    ResourceLoader resourceLoader;
    /**
     * Generate certificate
     *
     * @return certificate
     */
    public File getCertificate() {
        final File file = loadFile();
        if (file != null) {
            logCertificatePrivateKey(file);
            return file;
        } else {
            generateCertificate();
            return null;
        }
    }

    private File loadFile() {
        ClassLoader classLoader = AuthenticationService.class.getClassLoader();
        final URL resource = classLoader.getResource("data/keystore.jks");
        if (resource != null) {
            return new File(resource.getFile());
        }
        return null;
    }

    private void logCertificatePrivateKey(File file) {
        try {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(new FileInputStream(file), "mySecret".toCharArray());
            /*Certificate cert = keystore.getCertificate("jwtkey");
            PublicKey publicKey = cert.getPublicKey();*/
            System.out.println(keystore.getKey("jwtcert", secret.toCharArray()).toString());
        } catch (Exception e) {
            throw new OAuth2Exception("file.not.found");
        }
    }

    private void generateCertificate() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance(CERTIFICATE_ALGORITHM);
            gen.initialize(CERTIFICATE_BITS, SecureRandom.getInstance("SHA1PRNG"));
            KeyPair keyPair = gen.generateKeyPair();

            // GENERATE THE X509 CERTIFICATE
            X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();
            v3CertGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
            v3CertGen.setIssuerDN(new X509Principal(CERTIFICATE_DN));
            v3CertGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24));
            v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365 * 10)));
            v3CertGen.setSubjectDN(new X509Principal(CERTIFICATE_DN));
            v3CertGen.setPublicKey(keyPair.getPublic());
            v3CertGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
            X509Certificate cert = v3CertGen.generateX509Certificate(keyPair.getPrivate());
            saveCert(cert, keyPair.getPrivate());
        } catch (Exception e) {
            throw new OAuth2Exception("Retrieving keystore.jks file failed " + e.getMessage());
        }

    }

    private void saveCert(X509Certificate cert, PrivateKey key) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setKeyEntry(CERTIFICATE_ALIAS, key, secret.toCharArray(), new java.security.cert.Certificate[]{cert});
        File file = new File(".", CERTIFICATE_NAME);
        keyStore.store(new FileOutputStream(file), secret.toCharArray());
    }
}
