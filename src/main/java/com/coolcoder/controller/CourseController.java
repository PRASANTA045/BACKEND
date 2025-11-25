package com.coolcoder.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.coolcoder.dto.CenterDto;
import com.coolcoder.dto.CourseDto;
import com.coolcoder.dto.CreateCourseRequest;
import com.coolcoder.dto.UpdateCourseRequest;
import com.coolcoder.service.CourseService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/courses")
@RequiredArgsConstructor
public class CourseController {

	private final CourseService service;

	@PreAuthorize("hasRole('ADMIN')")
	@PostMapping
	public ResponseEntity<CourseDto> create(@Valid @RequestBody CreateCourseRequest request) {
		return ResponseEntity.ok(service.createCourse(request));
	}

//	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping
	public ResponseEntity<List<CourseDto>> getAll() {
		return ResponseEntity.ok(service.getAllCourses());
	}

	@GetMapping("/{id}")
	public ResponseEntity<CourseDto> getById(@PathVariable Long id) {
		return ResponseEntity.ok(service.getCourseById(id));
	}

	@PreAuthorize("hasRole('ADMIN')")
	@PutMapping("/{id}")
	public ResponseEntity<CourseDto> update(@PathVariable Long id, @Valid @RequestBody UpdateCourseRequest request) {

		return ResponseEntity.ok(service.updateCourse(id, request));
	}

	@PreAuthorize("hasRole('ADMIN')")
	@DeleteMapping("/{id}")
	public ResponseEntity<Void> delete(@PathVariable Long id) {
		service.deleteCourse(id);
		return ResponseEntity.noContent().build();
	}

	@GetMapping("/{id}/centers")
	public ResponseEntity<List<CenterDto>> getCentersByCourseId(@PathVariable Long id) {
		return ResponseEntity.ok(service.getCentersByCourseId(id));
	}

}
