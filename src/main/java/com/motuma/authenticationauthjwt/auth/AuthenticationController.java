package com.motuma.authenticationauthjwt.auth;

import com.motuma.authenticationauthjwt.config.JwtService;
import com.motuma.authenticationauthjwt.exception.TokenRefreshException;
import com.motuma.authenticationauthjwt.userModel.RefreshToken;
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
    private final JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {

        if (service.findByEmail(request.getEmail()).isPresent()) {
            ErrorResponse errorResponse= new ErrorResponse("User Exist");
            return new ResponseEntity<>(errorResponse, HttpStatus.IM_USED);
        }
        return ResponseEntity.ok(service.register(request));
    }
    @PostMapping("/register/admin")
    public ResponseEntity<?> registerAdmin(@RequestBody RegisterRequest request) {

        if (service.findByEmail(request.getEmail()).isPresent()) {
            ErrorResponse errorResponse= new ErrorResponse("User Exist");
            return new ResponseEntity<>(errorResponse, HttpStatus.IM_USED);
        }
        return ResponseEntity.ok(service.registerAdmin(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.authenticate(request));
    }
    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();
//        System.out.println(requestRefreshToken+ "The incommig refresh token request");
        return service.findByToken(requestRefreshToken)
                .map(service::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    var jwtToken=jwtService.generateToken(user);
                    return ResponseEntity.ok(new TokenRefreshResponse(jwtToken, requestRefreshToken));
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                        "Refresh token is not in database!"));
    }
    @Data
    class ErrorResponse{
        private String description;
        public ErrorResponse(String description) {
            this.description = description;
        }
    }

}
