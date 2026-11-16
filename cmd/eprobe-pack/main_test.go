package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testSeedHex is a FIXED TEST-ONLY Ed25519 seed. DO NOT use in production.
// This is deliberately different from any production key.
const testSeedHex = "0000000000000000000000000000000000000000000000000000000000000001"

var testKeyHex string

func init() {
	seed, _ := hex.DecodeString(testSeedHex)
	privKey := ed25519.NewKeyFromSeed(seed)
	testKeyHex = hex.EncodeToString(privKey)
}

func TestMainE2E(t *testing.T) {
	t.Setenv("EPROBE_SIGNING_KEY", testKeyHex)

	tempOutDir, err := os.MkdirTemp("", "eprobe-test-out-*")
	if err != nil {
		t.Fatalf("failed to create temp output directory: %v", err)
	}
	defer os.RemoveAll(tempOutDir)

	// Compute the project root without os.Chdir to avoid global state mutation (Finding #8)
	pkgDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get package directory: %v", err)
	}
	projectRoot := filepath.Join(pkgDir, "../..")
	projectRoot, err = filepath.Abs(projectRoot)
	if err != nil {
		t.Fatalf("failed to resolve project root: %v", err)
	}

	// Dynamically discover all target modules containing a manifest.yaml
	modulesDir := filepath.Join(projectRoot, "modules")
	var targetModules []string
	err = filepath.Walk(modulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			rel, err := filepath.Rel(modulesDir, path)
			if err != nil {
				return err
			}
			parts := strings.Split(filepath.ToSlash(rel), "/")
			if len(parts) == 2 {
				manifestPath := filepath.Join(path, "manifest.yaml")
				if _, err := os.Stat(manifestPath); err == nil {
					// Store path relative to project root for runWithRoot
					relToRoot, _ := filepath.Rel(projectRoot, path)
					targetModules = append(targetModules, relToRoot)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk modules directory: %v", err)
	}

	// Package each module individually using runWithRoot to avoid os.Chdir
	for _, modDir := range targetModules {
		err = runWithRoot(modDir, tempOutDir, "", projectRoot, false)
		if err != nil {
			t.Fatalf("run failed for module %q: %v", modDir, err)
		}
	}

	privBytes, _ := hex.DecodeString(testKeyHex)
	privKey := ed25519.PrivateKey(privBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)

	for _, modDir := range targetModules {
		// Use modulesDir-relative path for epm name computation
		rel, err := filepath.Rel(filepath.Join(projectRoot, "modules"), filepath.Join(projectRoot, modDir))
		if err != nil {
			t.Fatalf("failed to get relative path of %s: %v", modDir, err)
		}
		epmName := strings.ReplaceAll(filepath.ToSlash(rel), "/", "-") + ".epm"
		epmPath := filepath.Join(tempOutDir, epmName)
		if _, err := os.Stat(epmPath); err != nil {
			t.Errorf("expected package file %s does not exist", epmPath)
			continue
		}


		epmFile, err := os.Open(epmPath)
		if err != nil {
			t.Fatalf("failed to open package file: %v", err)
		}

		gr, err := gzip.NewReader(epmFile)
		if err != nil {
			epmFile.Close()
			t.Fatalf("failed to create gzip reader for %s: %v", epmName, err)
		}

		tr := tar.NewReader(gr)

		extractedFiles := make(map[string][]byte)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("failed to read tar header in %s: %v", epmName, err)
			}

			content, err := io.ReadAll(tr)
			if err != nil {
				t.Fatalf("failed to read file content for %s in %s: %v", hdr.Name, epmName, err)
			}
			extractedFiles[hdr.Name] = content
		}
		gr.Close()
		epmFile.Close()

		requiredFiles := []string{"manifest.yaml", "manifest.sig", "program.o"}
		for _, rf := range requiredFiles {
			if _, ok := extractedFiles[rf]; !ok {
				t.Errorf("missing required file %s in package %s", rf, epmName)
			}
		}

		manifestBytes := extractedFiles["manifest.yaml"]
		sigBytes := extractedFiles["manifest.sig"]
		objBytes := extractedFiles["program.o"]

		if !ed25519.Verify(pubKey, manifestBytes, sigBytes) {
			t.Errorf("cryptographic signature verification failed for package %s", epmName)
		}

		hasher := sha256.New()
		hasher.Write(objBytes)
		computedHash := hex.EncodeToString(hasher.Sum(nil))

		manifestStr := string(manifestBytes)
		var manifestHash string
		for _, line := range strings.Split(manifestStr, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "sha256:") {
				manifestHash = strings.TrimSpace(strings.TrimPrefix(trimmed, "sha256:"))
				break
			}
		}

		if manifestHash == "" {
			t.Errorf("sha256 field is missing from manifest.yaml in package %s", epmName)
		} else if manifestHash != computedHash {
			t.Errorf("sha256 mismatch in package %s: manifest had %s, computed %s", epmName, manifestHash, computedHash)
		}
	}
}

func TestUpdateSHA256(t *testing.T) {
	manifest := []byte("name: test-module\nversion: 1.0.0\nsha256: oldhashvalue\ndescription: \"Testing manifest update\"")

	newHash := "newhashvalue123456789"
	updated := updateSHA256(manifest, newHash)
	updatedStr := string(updated)

	if !strings.Contains(updatedStr, "sha256: newhashvalue123456789") {
		t.Errorf("failed to update existing sha256 in manifest. got:\n%s", updatedStr)
	}

	manifestNoHash := []byte("name: test-module\nversion: 1.0.0\ndescription: \"Testing manifest insert\"")

	inserted := updateSHA256(manifestNoHash, newHash)
	insertedStr := string(inserted)
	if !strings.Contains(insertedStr, "sha256: newhashvalue123456789") {
		t.Errorf("failed to insert sha256 in manifest. got:\n%s", insertedStr)
	}
}

func Test32ByteSeedKey(t *testing.T) {
	// The first 32 bytes (64 hex characters) of testKeyHex is a valid seed
	seedHex := testKeyHex[:64]
	t.Setenv("EPROBE_SIGNING_KEY", seedHex)

	tempOutDir, err := os.MkdirTemp("", "eprobe-test-seed-*")
	if err != nil {
		t.Fatalf("failed to create temp output directory: %v", err)
	}
	defer os.RemoveAll(tempOutDir)

	// Compute the project root without os.Chdir (Finding #8)
	pkgDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get package directory: %v", err)
	}
	projectRoot, err := filepath.Abs(filepath.Join(pkgDir, "../.."))
	if err != nil {
		t.Fatalf("failed to resolve project root: %v", err)
	}

	// Try running packaging on app/http-tracer using the 32-byte seed
	err = runWithRoot("modules/app/http-tracer", tempOutDir, "", projectRoot, false)
	if err != nil {
		t.Fatalf("run failed with 32-byte seed key: %v", err)
	}

	// Verify that the generated package exists
	epmPath := filepath.Join(tempOutDir, "app-http-tracer.epm")
	if _, err := os.Stat(epmPath); err != nil {
		t.Errorf("expected package file %s does not exist", epmPath)
	}
}

func TestUnsignedMode(t *testing.T) {
	t.Setenv("EPROBE_SIGNING_KEY", "")

	tempOutDir := t.TempDir()
	pkgDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get package directory: %v", err)
	}
	projectRoot, err := filepath.Abs(filepath.Join(pkgDir, "../.."))
	if err != nil {
		t.Fatalf("failed to resolve project root: %v", err)
	}

	if err := runWithRoot("modules/sys/syscall-xray", tempOutDir, "", projectRoot, true); err != nil {
		t.Fatalf("unsigned runWithRoot failed without EPROBE_SIGNING_KEY: %v", err)
	}

	epmPath := filepath.Join(tempOutDir, "sys-syscall-xray.epm")
	epmFile, err := os.Open(epmPath)
	if err != nil {
		t.Fatalf("failed to open unsigned package %s: %v", epmPath, err)
	}
	defer epmFile.Close()

	gr, err := gzip.NewReader(epmFile)
	if err != nil {
		t.Fatalf("failed to open gzip reader: %v", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	files := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("failed to read tar header: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("failed to read tar entry %s: %v", hdr.Name, err)
		}
		files[hdr.Name] = data
	}

	if _, hasSig := files["manifest.sig"]; hasSig {
		t.Error("expected unsigned .epm to omit manifest.sig")
	}
	manifestBytes, hasManifest := files["manifest.yaml"]
	if !hasManifest {
		t.Fatal("missing manifest.yaml in unsigned .epm")
	}
	objBytes, hasObj := files["program.o"]
	if !hasObj || len(objBytes) == 0 {
		t.Fatal("missing program.o in unsigned .epm")
	}

	sum := sha256.Sum256(objBytes)
	expectedHash := hex.EncodeToString(sum[:])
	if !strings.Contains(string(manifestBytes), "sha256: "+expectedHash) {
		t.Errorf("expected manifest.yaml to contain updated sha256 %s", expectedHash)
	}
}

