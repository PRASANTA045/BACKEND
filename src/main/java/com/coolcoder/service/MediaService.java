package com.coolcoder.service;

import java.util.List;

import org.springframework.web.multipart.MultipartFile;

import com.coolcoder.model.MediaFile;

public interface MediaService {

	public MediaFile uploadMedia(MultipartFile file, String adminName);

	public List<MediaFile> getAllMedia();

}
