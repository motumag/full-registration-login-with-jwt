package com.motuma.authenticationauthjwt.auth;

import com.motuma.authenticationauthjwt.config.JwtService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {

        if (service.findByEmail(request.getEmail()).isPresent()) {
            ErrorResponse errorResponse= new ErrorResponse("User Exist");
            return new ResponseEntity<>(errorResponse, HttpStatus.IM_USED);
        }
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.authenticate(request));
    }
    @Data
    class ErrorResponse{
        private String description;
        public ErrorResponse(String description) {
            this.description = description;
        }
    }

}
