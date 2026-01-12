package com.piromant.backend.service;

import com.piromant.backend.model.FileData;
import com.piromant.backend.repo.FileDataRepo;
import com.piromant.backend.repo.InodeRepo;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

@Service
public class FileDataService {

    private final FileDataRepo fileDataRepo;

    public FileDataService(FileDataRepo fileDataRepo, InodeService inodeService) {
        this.fileDataRepo = fileDataRepo;
    }

    @Transactional
    public FileData getFileData(Long ino) {
        return fileDataRepo.getFileDataByIno(ino);
    }


    @Transactional
    public FileData addDataToFile(byte[] addData, Long ino) {
        try {
            FileData fileData = fileDataRepo.getFileDataByIno(ino);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(fileData.getData());
            outputStream.write(addData);
            byte[] newData = outputStream.toByteArray();
            fileData.setData(newData);
            return fileDataRepo.save(fileData);
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public FileData createFileData(byte[] data, Long ino) {
        FileData fileData = new FileData(data, (long) data.length, ino);
        return fileDataRepo.save(fileData);
    }

    @Transactional
    public void delete(Long ino) {
        fileDataRepo.deleteFileDataByIno(ino);
    }
}
