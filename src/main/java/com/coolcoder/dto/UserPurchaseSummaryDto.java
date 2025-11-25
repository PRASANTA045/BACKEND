package com.coolcoder.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserPurchaseSummaryDto {

	private Long userId;
	private String fullName;
	private String email;

	private List<PurchasedCourseDto> purchases; // list of purchased courses
}
