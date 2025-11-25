package com.coolcoder.service;

import java.util.List;

import com.coolcoder.dto.CenterDto;
import com.coolcoder.dto.CreateCenterRequest;

public interface CenterService {

	CenterDto createCenter(CreateCenterRequest req);

	List<CenterDto> getAllCenters();
}
