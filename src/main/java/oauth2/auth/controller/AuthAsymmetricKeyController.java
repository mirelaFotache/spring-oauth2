package oauth2.auth.controller;

import oauth2.auth.service.CertificateService;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

@RestController
@RequestMapping(value = "/auth_asym_key")
public class AuthAsymmetricKeyController {

    private CertificateService certificateService;

    public AuthAsymmetricKeyController(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @RequestMapping("/certificate")
    public ResponseEntity<InputStreamResource> downloadCertificate() throws IOException {

        File file = certificateService.getCertificate();
        InputStreamResource resource = new InputStreamResource(new FileInputStream(file));

        return ResponseEntity.ok()
                // Content-Disposition
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment;filename=" + file.getName())
                // Content-Type
                .contentType(MediaType.parseMediaType("application/octet-stream"))
                // Contet-Length
                .contentLength(file.length()) //
                .body(resource);
    }


}
