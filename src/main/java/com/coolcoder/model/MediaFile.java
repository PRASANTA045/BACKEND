package com.coolcoder.model;

import java.util.Date;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "media_library")
@Setter
@Getter
@AllArgsConstructor
@RequiredArgsConstructor
public class MediaFile {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String fileName;
	private String fileType;
	private String fileUrl; // URL to access the file
	private Long fileSize; // in bytes

	private Date uploadedAt = new Date();

	private String uploadedBy; // ADMIN name or ID

	// getters and setters
}
