package com.coolcoder.service.impl;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.coolcoder.model.MediaFile;
import com.coolcoder.repository.MediaRepository;
import com.coolcoder.service.MediaService;

@Service
public class MediaServiceImpl implements MediaService {

	@Value("${media.upload-dir}")
	private String uploadDir;

	@Autowired
	private MediaRepository mediaRepository;

	@Override
	public MediaFile uploadMedia(MultipartFile file, String adminName) {

		try {
			File directory = new File(uploadDir);
			if (!directory.exists()) {
				directory.mkdirs();
			}

			String fileName = System.currentTimeMillis() + "_" + file.getOriginalFilename();

			Path filePath = Paths.get(uploadDir, fileName);
			Files.copy(file.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);

			MediaFile media = new MediaFile();
			media.setFileName(fileName);
			media.setFileType(file.getContentType());
			media.setFileSize(file.getSize());
			media.setUploadedBy(adminName);
			media.setFileUrl("/media/files/" + fileName);

			return mediaRepository.save(media);
		} catch (Exception e) {
			throw new RuntimeException("Failed to upload media file", e);
		}
	}

	@Override
	public List<MediaFile> getAllMedia() {
		return mediaRepository.findAll();
	}
}
