package com.coolcoder.dto;

import java.util.List;

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
public class CourseDto {
	private Long id;
	private String courseTitle;
	private String description;
	private String category;
	private String level;
	private String instructor;
	private String duration;
	private Double price;
	private String mode;
	private String imageUrl;
	private List<CenterDto> centers;

}
