package com.coolcoder.service;

import java.util.List;

import com.coolcoder.dto.PurchaseRequestDto;
import com.coolcoder.dto.PurchasedCourseDto;
import com.coolcoder.dto.UserPurchaseInfoDto;
import com.coolcoder.dto.UserPurchaseSummaryDto;
import com.coolcoder.model.CoursePurchase;

public interface PurchaseService {

	CoursePurchase purchaseCourse(PurchaseRequestDto request);

	List<CoursePurchase> getMyPurchases();

	List<CoursePurchase> getAllPurchases(); // admin only

	List<PurchasedCourseDto> getMyPurchasedCourses();

	UserPurchaseInfoDto getUserPurchaseDetails(Long userId);

	List<UserPurchaseSummaryDto> getAllUsersWithPurchases();

}
