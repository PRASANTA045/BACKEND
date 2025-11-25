package com.coolcoder.controller;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.coolcoder.dto.CreateUserRequest;
import com.coolcoder.dto.UserDto;
import com.coolcoder.service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:8080/")
public class UserController {

	private final UserService userService;

	@PostMapping
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<UserDto> create(@Valid @RequestBody CreateUserRequest request) {
		return ResponseEntity.ok(userService.create(request));
	}

	@GetMapping("/{id}")
	public ResponseEntity<UserDto> get(@PathVariable Long id) {
		return ResponseEntity.ok(userService.getById(id));
	}

	@GetMapping
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<Page<UserDto>> list(@RequestParam(defaultValue = "0") int page,
			@RequestParam(defaultValue = "10") int size) {

		return ResponseEntity.ok(userService.list(PageRequest.of(page, size)));
	}

	@GetMapping("/me")
	public ResponseEntity<UserDto> me() {
		return ResponseEntity.ok(userService.me());
	}

	@GetMapping("/all")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<List<UserDto>> getAll() {
		return ResponseEntity.ok(userService.getAllUsers());
	}

}
