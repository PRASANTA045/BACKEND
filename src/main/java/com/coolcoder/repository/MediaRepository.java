package com.coolcoder.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.coolcoder.model.MediaFile;

public interface MediaRepository extends JpaRepository<MediaFile, Long> {
}
