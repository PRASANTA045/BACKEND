package com.coolcoder.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.coolcoder.model.CoursePurchase;
import com.coolcoder.model.User;

public interface CoursePurchaseRepository extends JpaRepository<CoursePurchase, Long> {
	List<CoursePurchase> findByUser(User user);

	List<CoursePurchase> findByUserId(Long userId);

}
