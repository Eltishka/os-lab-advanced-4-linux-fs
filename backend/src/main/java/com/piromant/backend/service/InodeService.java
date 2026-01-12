package com.piromant.backend.service;

import com.piromant.backend.model.VtfsInode;
import com.piromant.backend.repo.InodeRepo;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.beans.Transient;
import java.util.List;

@Service
public class InodeService {
    private final InodeRepo repo;

    public List<VtfsInode> getInodes() {
        return repo.findAll();
    }

    public InodeService(InodeRepo repo) {
        this.repo = repo;
    }

    public VtfsInode getInodeByIno(Long ino) {
        return repo.findAllByIno(ino).getFirst();
    }

    public VtfsInode getInodeByParentIno(Long parentIno, String name) {
        VtfsInode inode = repo.findByParentInoAndName(parentIno, name);
        if(inode == null) {
            throw new RuntimeException("No such inode");
        }
        return inode;
    }

    public VtfsInode createInode(VtfsInode inode) {
        return repo.save(inode);
    }

    @Transactional
    public boolean deleteInode(Long ino, String name) {
        return repo.deleteByInoAndName(ino, name) > 0;
    }

    public long getMaxIno() {
        VtfsInode inode = repo.findTopByOrderByInoDesc();
        if(inode == null) {
            return 1000;
        }
        return inode.getIno();
    }


}
