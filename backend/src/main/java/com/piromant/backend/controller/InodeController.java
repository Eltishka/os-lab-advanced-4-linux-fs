package com.piromant.backend.controller;

import com.piromant.backend.model.VtfsInode;
import com.piromant.backend.service.InodeService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class InodeController {
    private final InodeService inodeService;

    public InodeController(InodeService inodeService) {
        this.inodeService = inodeService;
    }

    @GetMapping("/getAll")
    public List<VtfsInode> getInodes() {
        return inodeService.getInodes();
    }

    @GetMapping("/inodeByIno")
    public ResponseEntity<VtfsInode> getInodeByIno(@RequestParam Long ino) {
        return ResponseEntity.ok(inodeService.getInodeByIno(ino));
    }

    @GetMapping("/inodeByParentInoAndName")
    public ResponseEntity<VtfsInode> getInodeByInoAndName(@RequestParam Long parentIno, @RequestParam String name) {
        return ResponseEntity.ok(inodeService.getInodeByParentIno(parentIno, name));
    }

    @GetMapping("/createInode")
    public VtfsInode createInode(@RequestParam Long ino, @RequestParam Integer mode, @RequestParam String name, @RequestParam Long parentIno) {
        return inodeService.createInode(new VtfsInode(ino, mode, name, parentIno));
    }

    @DeleteMapping("/deleteInode")
    public boolean deleteInode(@RequestParam Long ino, @RequestParam String name) {
        return inodeService.deleteInode(ino, name);
    }

    @GetMapping("/getMaxIno")
    public long getMaxIno() {
        return inodeService.getMaxIno();
    }

}
