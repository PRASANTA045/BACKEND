package com.coolcoder.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.coolcoder.dto.PurchaseRequestDto;
import com.coolcoder.dto.PurchasedCourseDto;
import com.coolcoder.dto.UserPurchaseSummaryDto;
import com.coolcoder.model.CoursePurchase;
import com.coolcoder.service.PurchaseService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/purchase")
@RequiredArgsConstructor
@CrossOrigin("*")
public class PurchaseController {

	private final PurchaseService purchaseService;

	@PostMapping
	public ResponseEntity<CoursePurchase> purchase(@RequestBody PurchaseRequestDto request) {
		return ResponseEntity.ok(purchaseService.purchaseCourse(request));
	}

	@GetMapping("/my")
	public ResponseEntity<List<CoursePurchase>> myPurchases() {
		return ResponseEntity.ok(purchaseService.getMyPurchases());
	}

	@GetMapping("/all")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<List<CoursePurchase>> allPurchases() {
		return ResponseEntity.ok(purchaseService.getAllPurchases());
	}

	@GetMapping("/my-courses")
	public ResponseEntity<List<PurchasedCourseDto>> myPurchasedCourses() {
		return ResponseEntity.ok(purchaseService.getMyPurchasedCourses());
	}

	@GetMapping("/admin/user-purchases")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<List<UserPurchaseSummaryDto>> getUserPurchasesForAdmin() {
		return ResponseEntity.ok(purchaseService.getAllUsersWithPurchases());
	}

}
