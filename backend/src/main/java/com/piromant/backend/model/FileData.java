package com.piromant.backend.model;

import jakarta.persistence.*;

@Entity
@Table(name = "file_data")
public class FileData {

    @Id
    private Long ino;

    @Lob
    @Column(name = "data")
    private byte[] data;

    @Column(name = "size")
    private Long size;

    public FileData() {}

    public FileData(byte[] data, Long size, Long inode) {
        this.data = data;
        this.size = size;
        this.ino = inode;
    }

    public byte[] getData() { return data; }
    public void setData(byte[] data) { this.data = data; }

    public Long getSize() { return size; }
    public void setSize(Long size) { this.size = size; }

    public Long getInode() { return ino; }
    public void setInode(Long inode) { this.ino = inode; }
}