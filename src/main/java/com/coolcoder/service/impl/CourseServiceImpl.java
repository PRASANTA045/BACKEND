package com.coolcoder.service.impl;

import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.coolcoder.dto.CenterDto;
import com.coolcoder.dto.CourseDto;
import com.coolcoder.dto.CreateCourseRequest;
import com.coolcoder.dto.UpdateCourseRequest;
import com.coolcoder.exception.BadRequestException;
import com.coolcoder.exception.NotFoundException;
import com.coolcoder.model.Center;
import com.coolcoder.model.Course;
import com.coolcoder.repository.CenterRepository;
import com.coolcoder.repository.CourseRepository;
import com.coolcoder.service.CourseService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CourseServiceImpl implements CourseService {

	private final CourseRepository repo;
	private final CenterRepository centerRepository;

	@Override
	public CourseDto createCourse(CreateCourseRequest req) {

		if ((req.getMode().equalsIgnoreCase("offline") || req.getMode().equalsIgnoreCase("both"))
				&& (req.getCenterIds() == null || req.getCenterIds().isEmpty())) {

			throw new BadRequestException("At least one center is required");
		}

		List<Center> centers = centerRepository.findAllById(req.getCenterIds());

		Course course = Course.builder().courseTitle(req.getCourseTitle()).description(req.getDescription())
				.category(req.getCategory()).level(req.getLevel()).instructor(req.getInstructor())
				.duration(req.getDuration()).price(req.getPrice()).mode(req.getMode()).imageUrl(req.getImageUrl())
				.centers(centers).build();

		return toDto(repo.save(course));
	}

	@Override
	public CourseDto updateCourse(Long id, UpdateCourseRequest req) {

		Course course = repo.findById(id).orElseThrow(() -> new NotFoundException("Course not found"));

		course.setCourseTitle(req.getCourseTitle());
		course.setDescription(req.getDescription());
		course.setCategory(req.getCategory());
		course.setLevel(req.getLevel());
		course.setInstructor(req.getInstructor());
		course.setDuration(req.getDuration());
		course.setPrice(req.getPrice());
		course.setMode(req.getMode());
		course.setImageUrl(req.getImageUrl());

		if (req.getMode().equalsIgnoreCase("offline") || req.getMode().equalsIgnoreCase("both")) {
			if (req.getCenterIds() == null || req.getCenterIds().isEmpty()) {
				throw new BadRequestException("At least one center is required for offline/both mode");
			}
			List<Center> centers = centerRepository.findAllById(req.getCenterIds());
			course.setCenters(centers);
		} else {
			course.setCenters(null); // optional: clear centers for online-only
		}

		return toDto(repo.save(course));
	}

	@Override
	public void deleteCourse(Long id) {
		Course course = repo.findById(id).orElseThrow(() -> new RuntimeException("Course not found"));
		repo.delete(course);
	}

	@Override
	public List<CourseDto> getAllCourses() {
		return repo.findAll().stream().map(this::toDto).toList();
	}

	@Override
	public CourseDto getCourseById(Long id) {
		Course course = repo.findById(id).orElseThrow(() -> new NotFoundException("Course not found"));
		return toDto(course);
	}

	private CourseDto toDto(Course c) {
		return CourseDto.builder().id(c.getId()).courseTitle(c.getCourseTitle()).description(c.getDescription())
				.category(c.getCategory()).level(c.getLevel()).instructor(c.getInstructor()).duration(c.getDuration())
				.price(c.getPrice()).mode(c.getMode()).imageUrl(c.getImageUrl())
				.centers(c.getCenters().stream().map(center -> CenterDto.builder().id(center.getId())
						.centerName(center.getCenterName()).address(center.getAddress()).build()).toList())
				.build();
	}

	@Override
	@Transactional(readOnly = true)
	public List<CenterDto> getCentersByCourseId(Long courseId) {
		Course course = repo.findById(courseId)
				.orElseThrow(() -> new NotFoundException("Course not found with ID: " + courseId));

		return course.getCenters().stream()
				.map(center -> CenterDto.builder().id(center.getId()).centerName(center.getCenterName())
						.address(center.getAddress()).city(center.getCity()).state(center.getState())
						.contactNumber(center.getContactNumber()).build())
				.toList();
	}

}
