package com.coolcoder.controller;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.coolcoder.model.MediaFile;
import com.coolcoder.service.MediaService;

@RestController
@RequestMapping("/api/media")
@CrossOrigin(origins = "*")
public class MediaController {

	@Autowired
	private MediaService mediaService;

	@PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<?> uploadMedia(@RequestParam("file") MultipartFile file,
			@RequestParam("uploadedBy") String adminName) {
		try {
			MediaFile savedFile = mediaService.uploadMedia(file, adminName);
			return ResponseEntity.ok(savedFile);
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to upload file");
		}
	}

	@GetMapping("/all")
	public ResponseEntity<List<MediaFile>> getAllMedia() {
		return ResponseEntity.ok(mediaService.getAllMedia());
	}

	@GetMapping("/view/{fileName}")
	public ResponseEntity<byte[]> viewImage(@PathVariable String fileName) {
		try {
			Path path = Paths.get("uploads/media/" + fileName);

			if (!Files.exists(path)) {
				return ResponseEntity.notFound().build();
			}

			byte[] bytes = Files.readAllBytes(path);

			// detect image type automatically
			String contentType = Files.probeContentType(path);

			return ResponseEntity.ok().contentType(MediaType.parseMediaType(contentType)).body(bytes);

		} catch (Exception e) {
			return ResponseEntity.status(500).build();
		}
	}

}
