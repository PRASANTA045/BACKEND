package com.coolcoder.model;

import java.util.List;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "courses")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Course {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false)
	private String courseTitle;

	@Column(nullable = false, length = 2000)
	private String description;

	@Column(nullable = false)
	private String category;

	@Column(nullable = false)
	private String level;

	@Column(nullable = false)
	private String instructor;

	@Column(nullable = false)
	private String duration;

	@Column(nullable = false)
	private Double price;

	@Column(nullable = false)
	private String mode;

	private String imageUrl;

	@ManyToMany
	@JoinTable(name = "course_centers", joinColumns = @JoinColumn(name = "course_id"), inverseJoinColumns = @JoinColumn(name = "center_id"))
	private List<Center> centers;

}
