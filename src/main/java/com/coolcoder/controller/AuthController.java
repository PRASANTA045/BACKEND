package com.coolcoder.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
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
@CrossOrigin(origins = "http://localhost:8080/")
public class AuthController {

	private final AuthenticationManager authenticationManager;
	private final JwtService jwtService;
	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	@PostMapping("/register")
	public ResponseEntity<UserDto> register(@Valid @RequestBody CreateUserRequest request) {

	    // ⭐ NEW VALIDATION LOGIC ⭐
	    User existingUser = userRepository.findByEmail(request.getEmail()).orElse(null);

	    if (existingUser != null) {

	        // If name is DIFFERENT → BLOCK
	        if (!existingUser.getFullName().equalsIgnoreCase(request.getFullName())) {
	            throw new BadRequestException("This email is already registered with a different name.");
	        }

	        // If name is SAME → still block (email must be unique)
	        throw new BadRequestException("Email already registered. Please login.");
	    }

	    // Assign default role if null
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

	@PostMapping("/login")
	public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {

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

		return ResponseEntity.ok(AuthResponse.builder().token(token).build());
	}
}
