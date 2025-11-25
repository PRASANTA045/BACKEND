package com.coolcoder.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.coolcoder.model.Center;

public interface CenterRepository extends JpaRepository<Center, Long> {
}
