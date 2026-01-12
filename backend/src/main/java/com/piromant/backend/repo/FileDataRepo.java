package com.piromant.backend.repo;

import com.piromant.backend.model.FileData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface FileDataRepo extends JpaRepository<FileData, Integer> {
    FileData getFileDataByIno(Long ino);
    void deleteFileDataByIno(Long ino);
}
