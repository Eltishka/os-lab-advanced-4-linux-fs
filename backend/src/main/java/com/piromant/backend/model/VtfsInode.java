package com.piromant.backend.model;

import jakarta.persistence.*;

@Entity
@Table(name = "vtfs_inode")
public class VtfsInode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ino")
    private Long ino;

    @Column(name = "mode")
    private Integer mode;

    @Column(name = "name", length = 255)
    private String name;

    private Long parentIno;

    public VtfsInode() {}

    public VtfsInode(Long ino, Integer mode, String name, Long parent) {
        this.ino = ino;
        this.mode = mode;
        this.name = name;
        this.parentIno = parent;
    }


    public Long getIno() { return ino; }
    public void setIno(Long ino) { this.ino = ino; }

    public Integer getMode() { return mode; }
    public void setMode(Integer mode) { this.mode = mode; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public Long getParentIno() { return parentIno; }
    public void setParentIno(Long parent) { this.parentIno = parent; }

}