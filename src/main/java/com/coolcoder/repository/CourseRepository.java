package com.coolcoder.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.coolcoder.model.Course;

public interface CourseRepository extends JpaRepository<Course, Long> {
}
