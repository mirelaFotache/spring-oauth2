package oauth2.auth.controller;

import oauth2.auth.conmmunication.AuthenticationRequest;
import oauth2.auth.conmmunication.JWTTokenResponse;
import oauth2.auth.service.AuthenticationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/auth_sym_key")
public class AuthSymmetricKeyController {

    private AuthenticationService authenticationService;

    public AuthSymmetricKeyController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/token")
    public ResponseEntity<JWTTokenResponse> getToken(@RequestBody AuthenticationRequest request) {
        return new ResponseEntity<JWTTokenResponse>(authenticationService.generateJWTToken(request.getUsername(), request.getPassword()), HttpStatus.OK);
    }
}
