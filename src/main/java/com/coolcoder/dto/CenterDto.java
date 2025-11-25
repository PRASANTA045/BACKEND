package com.coolcoder.dto;

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
public class CenterDto {
	private Long id;
	private String centerName;
	private String address;
	private String city;
	private String state;
	private String contactNumber;
}
