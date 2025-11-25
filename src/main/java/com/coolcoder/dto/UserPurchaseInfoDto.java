package com.coolcoder.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class UserPurchaseInfoDto {

	private Long userId;
	private String fullName;
	private String email;

	private List<PurchasedCourseDto> purchases;
}
