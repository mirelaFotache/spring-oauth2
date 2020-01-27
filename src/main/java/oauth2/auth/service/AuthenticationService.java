package oauth2.auth.service;

import oauth2.exception.OAuth2Exception;
import oauth2.auth.conmmunication.JWTTokenResponse;
import oauth2.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private UserRepository userRepository;
    private JwtTokenService jwtTokenService;
    private PasswordEncoder passwordEncoder;

    @Autowired
    public AuthenticationService(UserRepository userRepository, JwtTokenService jwtTokenService, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.jwtTokenService = jwtTokenService;
        this.passwordEncoder = passwordEncoder;
    }

    public JWTTokenResponse generateJWTToken(String username, String password) {
        return userRepository.findByUsername(username)
                .filter(user ->  passwordEncoder.matches(password, user.getPassword()))
                .map(user -> new JWTTokenResponse(jwtTokenService.generateToken(user.getUsername(),user.getRoles())))
                .orElseThrow(() ->  new OAuth2Exception("account.not.found"));
    }

}
