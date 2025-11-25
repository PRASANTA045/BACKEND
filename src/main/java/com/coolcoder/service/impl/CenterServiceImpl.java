package com.coolcoder.service.impl;

import java.util.List;

import org.springframework.stereotype.Service;

import com.coolcoder.dto.CenterDto;
import com.coolcoder.dto.CreateCenterRequest;
import com.coolcoder.model.Center;
import com.coolcoder.repository.CenterRepository;
import com.coolcoder.service.CenterService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CenterServiceImpl implements CenterService {

	private final CenterRepository repo;

	@Override
	public CenterDto createCenter(CreateCenterRequest req) {

		Center center = Center.builder().centerName(req.getCenterName()).address(req.getAddress()).city(req.getCity())
				.state(req.getState()).contactNumber(req.getContactNumber()).build();

		Center saved = repo.save(center);

		return CenterDto.builder().id(saved.getId()).centerName(saved.getCenterName()).address(saved.getAddress())
				.city(saved.getCity()).state(saved.getState()).contactNumber(saved.getContactNumber()).build();
	}

	@Override
	public List<CenterDto> getAllCenters() {
		return repo.findAll().stream()
				.map(c -> CenterDto.builder().id(c.getId()).centerName(c.getCenterName()).address(c.getAddress())
						.city(c.getCity()).state(c.getState()).contactNumber(c.getContactNumber()).build())
				.toList();
	}
}
