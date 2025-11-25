package com.coolcoder.service.impl;

import org.springframework.stereotype.Service;

import com.coolcoder.dto.CreateBatchRequest;
import com.coolcoder.exception.NotFoundException;
import com.coolcoder.model.Batch;
import com.coolcoder.model.Center;
import com.coolcoder.model.Course;
import com.coolcoder.repository.BatchRepository;
import com.coolcoder.repository.CenterRepository;
import com.coolcoder.repository.CourseRepository;
import com.coolcoder.service.BatchService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class BatchServiceImpl implements BatchService {

	private final BatchRepository batchRepo;
	private final CourseRepository courseRepo;
	private final CenterRepository centerRepo;

	@Override
	public void createBatch(CreateBatchRequest req) {

		Course course = courseRepo.findById(req.getCourseId())
				.orElseThrow(() -> new NotFoundException("Course not found"));

		Center center = null;

		if (req.getMode().equalsIgnoreCase("offline")) {
			center = centerRepo.findById(req.getCenterId())
					.orElseThrow(() -> new NotFoundException("Center not found"));
		}

		Batch batch = Batch.builder().batchName(req.getBatchName()).course(course).mode(req.getMode()).center(center)
				.startDate(req.getStartDate()).endDate(req.getEndDate()).build();

		batchRepo.save(batch);
	}
}
