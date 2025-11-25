package com.coolcoder.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.coolcoder.model.Batch;

public interface BatchRepository extends JpaRepository<Batch, Long> {
}
