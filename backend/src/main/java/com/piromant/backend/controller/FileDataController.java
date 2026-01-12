package com.piromant.backend.controller;

import com.piromant.backend.model.FileData;
import com.piromant.backend.service.FileDataService;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.HexFormat;

@RestController
public class FileDataController {

    private final FileDataService fileDataService;

    public FileDataController(FileDataService fileDataService) {
        this.fileDataService = fileDataService;
    }

    @GetMapping("/fileByIno")
    public FileData getFileData(@RequestParam Long ino) {
        return fileDataService.getFileData(ino);
    }

    @PutMapping("/files")
    public FileData append(
            @RequestParam Long ino,
            @RequestParam String addData
    ) {
        byte[] data = Base64.getDecoder().decode(addData);
        return fileDataService.addDataToFile(data, ino);
    }

    @PostMapping("/files")
    public FileData overwrite(
            @RequestParam Long ino,
            @RequestParam String data
    ) {
        byte[] bytes = Base64.getDecoder().decode(data);
        return fileDataService.createFileData(bytes, ino);
    }


    @DeleteMapping("/deleteFile")
    public boolean deleteFileData(@RequestParam Long ino) {
        fileDataService.delete(ino);
        return true;
    }
}
