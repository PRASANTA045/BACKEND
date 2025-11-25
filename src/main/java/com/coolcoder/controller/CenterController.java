package com.coolcoder.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.coolcoder.dto.CenterDto;
import com.coolcoder.dto.CreateCenterRequest;
import com.coolcoder.service.CenterService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/centers")
@RequiredArgsConstructor
public class CenterController {

	private final CenterService service;

	@PreAuthorize("hasRole('ADMIN')")
	@PostMapping
	public ResponseEntity<CenterDto> create(@RequestBody CreateCenterRequest req) {
		return ResponseEntity.ok(service.createCenter(req));
	}

	@GetMapping
	public ResponseEntity<List<CenterDto>> getAll() {
		return ResponseEntity.ok(service.getAllCenters());
	}
}
