package com.coolcoder.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "batches")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Batch {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String batchName;

	@ManyToOne
	@JoinColumn(name = "course_id", nullable = false)
	private Course course;

	// If mode = offline → centerId is required
	@ManyToOne
	@JoinColumn(name = "center_id")
	private Center center;

	private String mode; // "online" / "offline"
	private String startDate;
	private String endDate;
}
