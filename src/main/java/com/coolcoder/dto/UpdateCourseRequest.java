package com.coolcoder.dto;

import java.util.List;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateCourseRequest {

	@NotBlank
	private String courseTitle;

	@NotBlank
	private String description;

	@NotBlank
	private String category;

	@NotBlank
	private String level;

	@NotBlank
	private String instructor;

	@NotBlank
	private String duration;

	@Min(0)
	private Double price;

	@NotBlank
	private String mode;

	private String imageUrl;
	
	private List<Long> centerIds;

}
