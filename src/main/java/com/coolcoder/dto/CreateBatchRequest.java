package com.coolcoder.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CreateBatchRequest {

	private String batchName;
	private Long courseId;
	private String mode; // online or offline
	private Long centerId; // required only if offline
	private String startDate;
	private String endDate;
}
