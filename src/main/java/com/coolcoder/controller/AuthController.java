package com.coolcoder.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

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

        User existing = userRepository.findByEmail(request.getEmail()).orElse(null);
        if (existing != null) {

            if (!existing.getFullName().equalsIgnoreCase(request.getFullName())) {
                throw new BadRequestException("This email is already registered with a different name.");
            }
            throw new BadRequestException("Email already registered. Please login.");
        }

        Role role = request.getRole() == null ? Role.USER : request.getRole();

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
                        .role(user.getRole().name())
                        .createdAt(user.getCreatedAt())
                        .build()
        );
    }

    // ===========================
    // LOGIN
    // ===========================
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody AuthRequest request,
                                   HttpServletResponse response) {

        // Validate user credentials
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        // Fetch user
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new NotFoundException("User not found"));

        // ⭐ Generate token FROM ENTITY (this includes role)
        String token = jwtService.generateToken(user);

        // ⭐ Set Cookie
        Cookie cookie = new Cookie("jwt", token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);         // Required for Vercel/HTTPS
        cookie.setPath("/");
        cookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
        response.addCookie(cookie);

        return ResponseEntity.ok(
                AuthResponse.builder()
                        .message("Login successful")
                        .user(
                                UserDto.builder()
                                        .id(user.getId())
                                        .fullName(user.getFullName())
                                        .email(user.getEmail())
                                        .role(user.getRole().name())   // Send ADMIN / USER
                                        .createdAt(user.getCreatedAt())
                                        .build()
                        )
                        .build()
        );
    }
}
