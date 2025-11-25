package com.coolcoder.dto;

import java.util.List;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CreateCourseRequest {

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

	@NotNull
	@Min(0)
	private Double price;

	@NotBlank
	private String mode;

	private String imageUrl;

	private List<Long> centerIds;

}
