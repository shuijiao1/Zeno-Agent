package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReopenLogWriterFollowsExternalRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zeno-agent.log")
	writer := &reopenLogWriter{path: path}
	if _, err := writer.Write([]byte("before rotation\n")); err != nil {
		t.Fatalf("write before rotation: %v", err)
	}
	rotated := path + ".0"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatalf("rotate log: %v", err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create replacement log: %v", err)
	}
	if _, err := writer.Write([]byte("after rotation\n")); err != nil {
		t.Fatalf("write after rotation: %v", err)
	}
	oldData, err := os.ReadFile(rotated)
	if err != nil {
		t.Fatalf("read rotated log: %v", err)
	}
	newData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replacement log: %v", err)
	}
	if string(oldData) != "before rotation\n" || string(newData) != "after rotation\n" {
		t.Fatalf("rotated/new logs = %q / %q", oldData, newData)
	}
}

func TestReopenLogWriterRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "zeno-agent.log")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := (&reopenLogWriter{path: path}).Write([]byte("unsafe\n")); err == nil {
		t.Fatal("reopen writer accepted a symlink")
	}
}
