package com.coolcoder.service.impl;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.coolcoder.dto.CreateUserRequest;
import com.coolcoder.dto.UserDto;
import com.coolcoder.exception.BadRequestException;
import com.coolcoder.exception.NotFoundException;
import com.coolcoder.model.Role;
import com.coolcoder.model.User;
import com.coolcoder.repository.UserRepository;
import com.coolcoder.service.UserService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	@Override
	public UserDto create(CreateUserRequest request) {
		if (userRepository.existsByEmail(request.getEmail())) {
			throw new BadRequestException("Email already exists");
		}

		Role role = request.getRole() == null ? Role.USER : request.getRole();

		User user = User.builder().fullName(request.getFullName()).email(request.getEmail())
				.password(passwordEncoder.encode(request.getPassword())).role(role).build();

		userRepository.save(user);

		return toDto(user);
	}

	@Override
	public UserDto getById(Long id) {
		User user = userRepository.findById(id).orElseThrow(() -> new NotFoundException("User not found"));
		return toDto(user);
	}

	@Override
	public Page<UserDto> list(Pageable pageable) {
		return userRepository.findAll(pageable).map(this::toDto);
	}

	@Override
	public UserDto me() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		User user = userRepository.findByEmail(auth.getName())
				.orElseThrow(() -> new NotFoundException("User not found"));
		return toDto(user);
	}

	private UserDto toDto(User u) {
		return UserDto.builder().id(u.getId()).fullName(u.getFullName()).email(u.getEmail()).role(u.getRole())
				.createdAt(u.getCreatedAt()).build();
	}

	@Override
	public List<UserDto> getAllUsers() {
		return userRepository.findAll().stream().map(this::toDto).toList();
	}

}
