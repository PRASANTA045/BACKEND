package com.coolcoder.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.coolcoder.dto.AuthRequest;
import com.coolcoder.dto.AuthResponse;
import com.coolcoder.dto.CreateUserRequest;
import com.coolcoder.dto.UserDto;
import com.coolcoder.exception.BadRequestException;
import com.coolcoder.exception.NotFoundException;
import com.coolcoder.model.Role;
import com.coolcoder.model.User;
import com.coolcoder.repository.UserRepository;
import com.coolcoder.security.JwtService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // ===========================
    // REGISTER
    // ===========================
    @PostMapping("/register")
    public ResponseEntity<UserDto> register(@Valid @RequestBody CreateUserRequest request) {

        // Check if email exists
        User existingUser = userRepository.findByEmail(request.getEmail()).orElse(null);

        if (existingUser != null) {

            // Name different → block
            if (!existingUser.getFullName().equalsIgnoreCase(request.getFullName())) {
                throw new BadRequestException("This email is already registered with a different name.");
            }

            // Name same → still block
            throw new BadRequestException("Email already registered. Please login.");
        }

        // Assign default user role
        Role role = request.getRole() == null ? Role.USER : request.getRole();

        // Create new user
        User user = User.builder()
                .fullName(request.getFullName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(role)
                .build();

        userRepository.save(user);

        return ResponseEntity.ok(
                UserDto.builder()
                        .id(user.getId())
                        .fullName(user.getFullName())
                        .email(user.getEmail())
                        .role(user.getRole())
                        .createdAt(user.getCreatedAt())
                        .build()
        );
    }

    // ===========================
    // LOGIN
    // ===========================
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody AuthRequest request) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new NotFoundException("User not found"));

        String token = jwtService.generateToken(
                org.springframework.security.core.userdetails.User
                        .withUsername(user.getEmail())
                        .password(user.getPassword())
                        .roles(user.getRole().name())
                        .build()
        );

        // ===========================
        //    SET HTTP-ONLY COOKIE
        // ===========================
        ResponseCookie cookie = ResponseCookie.from("jwt", token)
                .httpOnly(true)
                .secure(true)          // required for Vercel (HTTPS)
                .sameSite("None")      // required for cross-site cookies
                .path("/")
                .maxAge(7 * 24 * 60 * 60) // 7 days
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(
                        AuthResponse.builder()
                                .message("Login successful")
                                .user(user)
                                .build()
                );
    }
}
