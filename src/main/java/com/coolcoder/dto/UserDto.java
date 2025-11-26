package com.coolcoder.dto;

import java.time.Instant;



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
public class UserDto {
	private Long id;
	private String fullName;
	private String email;
	private String role;
	private Instant createdAt;
}
