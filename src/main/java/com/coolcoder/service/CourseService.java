package com.coolcoder.service;

import java.util.List;

import com.coolcoder.dto.CenterDto;
import com.coolcoder.dto.CourseDto;
import com.coolcoder.dto.CreateCourseRequest;
import com.coolcoder.dto.UpdateCourseRequest;

public interface CourseService {
	CourseDto createCourse(CreateCourseRequest request);

	CourseDto updateCourse(Long id, UpdateCourseRequest request);

	void deleteCourse(Long id);

	List<CourseDto> getAllCourses();

	CourseDto getCourseById(Long id);

	List<CenterDto> getCentersByCourseId(Long courseId);
}
