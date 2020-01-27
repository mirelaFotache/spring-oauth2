package oauth2.auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import oauth2.exception.OAuth2Exception;
import oauth2.user.model.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtTokenService {

    @Autowired
    ResourceLoader resourceLoader;

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    public static final String KEYSTORE_FILE_NOT_FOUND = "keystore.file.not.found";

    public JwtTokenService(){}

    public String generateToken(String username, List<Role> roles) {
        Claims claims = Jwts.claims();
        claims.put("auth", roles.stream().map(s -> new SimpleGrantedAuthority
                (s.getAuthority())).collect(Collectors.toList()));

        final Date createdDate = new Date();
        final Date expirationDate = calculateExpirationDate(createdDate);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(createdDate)
                .setExpiration(expirationDate)
                //.signWith(SignatureAlgorithm.HS512, secret) // Use symmetric key retrieved from yaml file with @Value. Algorithm used: HS512
                .signWith(SignatureAlgorithm.RS512, getPrivateKey()) // Use asymmetric key. Algorithm used: RS512
                .compact();
    }

    private Date calculateExpirationDate(Date createdDate) {
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
        try {
            return formatter.parse("2400-12-31");
        }catch(Exception e){}
        //return new Date(createdDate.getTime() + 604800);
        return null;
    }

    private Key getPrivateKey() {
        try {
            ClassLoader classLoader = JwtTokenService.class.getClassLoader();

            final URL resource = classLoader.getResource("data/keystore.jks");
            if (resource!=null) {
            File file = new File(resource.getFile());
                KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                keystore.load(new FileInputStream(file), secret.toCharArray());
                /*Certificate cert = keystore.getCertificate("jwtkey");
                PublicKey publicKey = cert.getPublicKey();*/
                return keystore.getKey("jwtcert", secret.toCharArray());
            } else {
                throw new OAuth2Exception("Keystore file not available");
            }
        } catch (Exception e) {
            throw new OAuth2Exception(KEYSTORE_FILE_NOT_FOUND);
        }
    }
}
