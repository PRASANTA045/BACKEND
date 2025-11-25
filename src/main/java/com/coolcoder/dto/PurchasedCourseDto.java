package com.coolcoder.dto;

import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PurchasedCourseDto {
	private Long purchaseId;
	private Long courseId;
	private String courseTitle;
	private String instructor;
	private String mode;
	private String centerId;
	private Instant purchaseDate;
	private String paymentStatus;
}
