package com.coolcoder.service.impl;

import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.coolcoder.dto.PurchaseRequestDto;
import com.coolcoder.dto.PurchasedCourseDto;
import com.coolcoder.dto.UserPurchaseInfoDto;
import com.coolcoder.dto.UserPurchaseSummaryDto;
import com.coolcoder.exception.NotFoundException;
import com.coolcoder.model.Course;
import com.coolcoder.model.CoursePurchase;
import com.coolcoder.model.User;
import com.coolcoder.repository.CoursePurchaseRepository;
import com.coolcoder.repository.CourseRepository;
import com.coolcoder.repository.UserRepository;
import com.coolcoder.service.PurchaseService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class PurchaseServiceImpl implements PurchaseService {

	private final CoursePurchaseRepository purchaseRepo;
	private final UserRepository userRepo;
	private final CourseRepository courseRepo;

	@Override
	public CoursePurchase purchaseCourse(PurchaseRequestDto request) {

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		User user = userRepo.findByEmail(auth.getName()).orElseThrow(() -> new NotFoundException("User not found"));

		Course course = courseRepo.findById(request.getCourseId())
				.orElseThrow(() -> new NotFoundException("Course not found"));

		CoursePurchase purchase = CoursePurchase.builder().user(user).course(course).mode(request.getMode())
				.centerId(request.getCenterId()).paymentStatus("SUCCESS") // change later for Razorpay
				.build();

		return purchaseRepo.save(purchase);
	}

	@Override
	public List<CoursePurchase> getMyPurchases() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		User user = userRepo.findByEmail(auth.getName()).orElseThrow(() -> new NotFoundException("User not found"));

		return purchaseRepo.findByUser(user);
	}

	@Override
	public List<CoursePurchase> getAllPurchases() {
		return purchaseRepo.findAll();
	}

	@Override
	public List<PurchasedCourseDto> getMyPurchasedCourses() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		User user = userRepo.findByEmail(auth.getName()).orElseThrow(() -> new NotFoundException("User not found"));

		return purchaseRepo.findByUser(user).stream()
				.map(p -> PurchasedCourseDto.builder().purchaseId(p.getId()).courseId(p.getCourse().getId())
						.courseTitle(p.getCourse().getCourseTitle()).instructor(p.getCourse().getInstructor())
						.mode(p.getMode()).centerId(p.getCenterId()).purchaseDate(p.getPurchaseDate())
						.paymentStatus(p.getPaymentStatus()).build())
				.toList();
	}

	@Override
	public UserPurchaseInfoDto getUserPurchaseDetails(Long userId) {

		User user = userRepo.findById(userId).orElseThrow(() -> new NotFoundException("User not found"));

		List<CoursePurchase> purchases = purchaseRepo.findByUserId(userId);

		List<PurchasedCourseDto> purchasedCourses = purchases.stream()
				.map(p -> PurchasedCourseDto.builder().purchaseId(p.getId()).courseId(p.getCourse().getId())
						.courseTitle(p.getCourse().getCourseTitle()).instructor(p.getCourse().getInstructor())
						.mode(p.getMode()).centerId(p.getCenterId()).purchaseDate(p.getPurchaseDate())
						.paymentStatus(p.getPaymentStatus()).build())
				.toList();

		return UserPurchaseInfoDto.builder().userId(user.getId()).fullName(user.getFullName()).email(user.getEmail())
				.purchases(purchasedCourses).build();
	}

	@Override
	public List<UserPurchaseSummaryDto> getAllUsersWithPurchases() {

		List<User> allUsers = userRepo.findAll();

		return allUsers.stream().map(user -> {

			// Fetch purchases for this user
			List<CoursePurchase> userPurchases = purchaseRepo.findByUser(user);

			List<PurchasedCourseDto> purchasedCourses = userPurchases.stream()
					.map(p -> PurchasedCourseDto.builder().purchaseId(p.getId()).courseId(p.getCourse().getId())
							.courseTitle(p.getCourse().getCourseTitle()).instructor(p.getCourse().getInstructor())
							.mode(p.getMode()).centerId(p.getCenterId()).purchaseDate(p.getPurchaseDate())
							.paymentStatus(p.getPaymentStatus()).build())
					.toList();

			return UserPurchaseSummaryDto.builder().userId(user.getId()).fullName(user.getFullName())
					.email(user.getEmail()).purchases(purchasedCourses).build();

		}).toList();
	}

}
