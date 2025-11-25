package com.coolcoder.dto;

import com.coolcoder.model.Role;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CreateUserRequest {
	@NotBlank
	private String fullName;

	@Email
	@NotBlank
	private String email;

	@NotBlank
	private String password;

// Optional; defaults to USER if null
	private Role role;
}