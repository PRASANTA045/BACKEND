package com.coolcoder.service;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.coolcoder.dto.CreateUserRequest;
import com.coolcoder.dto.UserDto;

public interface UserService {
	UserDto create(CreateUserRequest request);

	UserDto getById(Long id);

	Page<UserDto> list(Pageable pageable);

	UserDto me();

	List<UserDto> getAllUsers();
}
