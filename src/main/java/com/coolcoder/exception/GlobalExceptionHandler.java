package com.coolcoder.exception;

import java.time.Instant;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.coolcoder.dto.ApiError;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;

@RestControllerAdvice
public class GlobalExceptionHandler {

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex, HttpServletRequest req) {
		List<String> violations = ex.getBindingResult().getFieldErrors().stream()
				.map(f -> f.getField() + ": " + f.getDefaultMessage()).toList();

		ApiError error = ApiError.builder().timestamp(Instant.now()).status(HttpStatus.BAD_REQUEST.value())
				.error("Validation Failed").message("Invalid request body").path(req.getRequestURI())
				.violations(violations).build();

		return ResponseEntity.badRequest().body(error);
	}

	@ExceptionHandler(ConstraintViolationException.class)
	public ResponseEntity<ApiError> handleConstraintViolation(ConstraintViolationException ex, HttpServletRequest req) {
		ApiError error = ApiError.builder().timestamp(Instant.now()).status(HttpStatus.BAD_REQUEST.value())
				.error("Constraint Violation").message(ex.getMessage()).path(req.getRequestURI()).build();

		return ResponseEntity.badRequest().body(error);
	}

	@ExceptionHandler(BadRequestException.class)
	public ResponseEntity<ApiError> handleBadRequest(BadRequestException ex, HttpServletRequest req) {
		ApiError error = ApiError.builder().timestamp(Instant.now()).status(HttpStatus.BAD_REQUEST.value())
				.error("Bad Request").message(ex.getMessage()).path(req.getRequestURI()).build();

		return ResponseEntity.badRequest().body(error);
	}

	@ExceptionHandler(NotFoundException.class)
	public ResponseEntity<ApiError> handleNotFound(NotFoundException ex, HttpServletRequest req) {
		ApiError error = ApiError.builder().timestamp(Instant.now()).status(HttpStatus.NOT_FOUND.value())
				.error("Not Found").message(ex.getMessage()).path(req.getRequestURI()).build();

		return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ApiError> handleGenericException(Exception ex, HttpServletRequest req) {
		ApiError error = ApiError.builder().timestamp(Instant.now()).status(HttpStatus.INTERNAL_SERVER_ERROR.value())
				.error("Internal Server Error").message(ex.getMessage()).path(req.getRequestURI()).build();

		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
	}
}
