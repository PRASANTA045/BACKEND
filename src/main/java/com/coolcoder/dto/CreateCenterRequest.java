package com.coolcoder.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CreateCenterRequest {
	private String centerName;
	private String address;
	private String city;
	private String state;
	private String contactNumber;
}
