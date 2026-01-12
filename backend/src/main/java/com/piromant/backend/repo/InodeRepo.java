package com.piromant.backend.repo;

import com.piromant.backend.model.VtfsInode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface InodeRepo extends JpaRepository<VtfsInode, Long> {
    List<VtfsInode> findAllByIno(Long ino);
    List<VtfsInode> findAllByParentIno(Long parentIno);
    VtfsInode findByParentInoAndName(Long ino, String name);
    long deleteByInoAndName(Long ino, String name);
    VtfsInode findTopByOrderByInoDesc();

}
