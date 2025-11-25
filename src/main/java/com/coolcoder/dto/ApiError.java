package com.coolcoder.dto;

import java.time.Instant;
import java.util.List;

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
public class ApiError {
	private Instant timestamp;
	private int status;
	private String error;
	private String message;
	private String path;
	private List<String> violations; // for validation errors
}