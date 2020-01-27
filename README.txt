The difference on server side between using symmetric and asymmetric keys is in the way token is built.
Using symmetric keys:
 - Build token and sign it with the symmetric key:
 return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(createdDate)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS512, secret) // Use symmetric key retrieved from yaml file with @Value. Algorithm used: HS512
                .compact();

Using asymmetric keys:
 - Generate certificate and provide an URL to download it
 - Build token and sign it with the private key:
  return Jwts.builder()
                 .setClaims(claims)
                 .setSubject(username)
                 .setIssuedAt(createdDate)
                 .setExpiration(expirationDate)
                 .signWith(SignatureAlgorithm.RS512, getPrivateKey()) // Use asymmetric key. Algorithm used: RS512
                 .compact();
  - Provide an URL to retrieve token