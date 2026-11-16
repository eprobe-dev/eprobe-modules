package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// manifestDoc represents the top-level fields of a manifest.yaml that eprobe-pack needs to read.
type manifestDoc struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
	SHA256  string `yaml:"sha256"`
}

func main() {
	dirFlag := flag.String("dir", "", "Target subdirectory containing raw C files and manifests (e.g., modules/sec/exec-audit/)")
	outDirFlag := flag.String("output-dir", "./dist", "Where to save the generated .epm file")
	autoBumpFlag := flag.String("auto-bump", "", "Automatically bump semantic version in manifest.yaml (patch, minor, major) before packaging")
	unsignedFlag := flag.Bool("unsigned", false, "Compile and package .epm without signing (skips EPROBE_SIGNING_KEY and omits manifest.sig)")
	flag.Parse()

	if *dirFlag == "" {
		fmt.Fprintln(os.Stderr, "Error: --dir flag must be specified.")
		flag.Usage()
		os.Exit(1)
	}

	if err := run(*dirFlag, *outDirFlag, *autoBumpFlag, *unsignedFlag); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// run is the production entry point that uses os.Getwd() as the workspace root.
func run(targetDir, outDir, autoBump string, unsigned bool) error {
	workspaceRoot, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}
	return runWithRoot(targetDir, outDir, autoBump, workspaceRoot, unsigned)
}

// runWithRoot is the core logic, accepting an explicit workspace root to avoid
// global os.Chdir() mutations in tests (Finding #8).
func runWithRoot(targetDir, outDir, autoBump, workspaceRoot string, unsigned bool) error {
	// 1. Read and validate EPROBE_SIGNING_KEY (skipped in --unsigned mode)
	var privKey ed25519.PrivateKey
	if !unsigned {
		signingKeyHex := os.Getenv("EPROBE_SIGNING_KEY")
		if signingKeyHex == "" {
			return fmt.Errorf("EPROBE_SIGNING_KEY environment variable is not set (pass --unsigned for local unsigned builds)")
		}
		privBytes, err := hex.DecodeString(signingKeyHex)
		if err != nil {
			return fmt.Errorf("failed to decode EPROBE_SIGNING_KEY hex string: %w", err)
		}
		if len(privBytes) == 32 {
			privKey = ed25519.NewKeyFromSeed(privBytes)
		} else if len(privBytes) == 64 {
			privKey = ed25519.PrivateKey(privBytes)
		} else {
			return fmt.Errorf("EPROBE_SIGNING_KEY must be either 32 bytes (64 hex characters seed) or 64 bytes (128 hex characters private key), got %d bytes", len(privBytes))
		}
	}

	// Clean and resolve target directory against workspace root
	cleanTargetDir := filepath.Clean(targetDir)
	var absTargetDir string
	if filepath.IsAbs(cleanTargetDir) {
		absTargetDir = cleanTargetDir
	} else {
		absTargetDir = filepath.Join(workspaceRoot, cleanTargetDir)
	}
	absTargetDir, err := filepath.Abs(absTargetDir)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path of target directory: %w", err)
	}

	// Verify target directory exists and is indeed a directory
	dirInfo, err := os.Stat(absTargetDir)
	if err != nil {
		return fmt.Errorf("target directory does not exist: %w", err)
	}
	if !dirInfo.IsDir() {
		return fmt.Errorf("target path is not a directory: %s", absTargetDir)
	}

	// Enforce workspace sandbox boundaries
	absWorkspaceRoot, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute workspace root path: %w", err)
	}
	sandboxPrefix := absWorkspaceRoot
	if !strings.HasSuffix(sandboxPrefix, string(filepath.Separator)) {
		sandboxPrefix += string(filepath.Separator)
	}

	if !strings.HasPrefix(absTargetDir, sandboxPrefix) && absTargetDir != absWorkspaceRoot {
		return fmt.Errorf("security violation: target directory %q is outside workspace directory %q", absTargetDir, absWorkspaceRoot)
	}
	if absTargetDir == absWorkspaceRoot {
		return fmt.Errorf("target directory must be a subdirectory of the workspace, not the workspace root itself: %s", absWorkspaceRoot)
	}

	// Verify manifest.yaml exists
	manifestPath := filepath.Join(absTargetDir, "manifest.yaml")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		return fmt.Errorf("manifest.yaml is missing in target directory: %s", absTargetDir)
	}

	// Formulate expected .c filename (replace '-' with '_')
	dirName := filepath.Base(absTargetDir)
	cFileName := strings.ReplaceAll(dirName, "-", "_") + ".c"
	cFilePath := filepath.Join(absTargetDir, cFileName)

	// Verify matching .c source file exists
	if _, err := os.Stat(cFilePath); os.IsNotExist(err) {
		return fmt.Errorf("matching source file %q is missing in target directory: %s", cFileName, absTargetDir)
	}

	// 2. Ensure output directory exists
	err = os.MkdirAll(outDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create output directory %s: %w", outDir, err)
	}

	// 3. Process the module
	if err := processModule(absTargetDir, cFilePath, manifestPath, outDir, privKey, absWorkspaceRoot, autoBump, unsigned); err != nil {
		return fmt.Errorf("failed to process module: %w", err)
	}

	return nil
}

func processModule(targetDir, srcCPath, manifestPath, outDir string, privKey ed25519.PrivateKey, workspaceRoot, autoBump string, unsigned bool) error {
	fmt.Printf("Processing module in: %s\n", targetDir)

	// Create a temporary build workspace
	tempDir, err := os.MkdirTemp("", "eprobe-pack-build-*")
	if err != nil {
		return fmt.Errorf("failed to create temp build directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	tempObjectPath := filepath.Join(tempDir, "program.o")

	cmd := exec.Command("clang",
		"-target", "bpf",
		"-O2",
		"-g",
		"-Wall",
		"-Iinclude",
		"-D__TARGET_ARCH_x86",
		"-c", srcCPath,
		"-o", tempObjectPath,
	)
	cmd.Dir = workspaceRoot

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("clang compilation failed: %v\nstderr: %s", err, stderr.String())
	}

	// Compute SHA256 of compiled program.o
	objBytes, err := os.ReadFile(tempObjectPath)
	if err != nil {
		return fmt.Errorf("failed to read compiled program.o: %w", err)
	}
	hasher := sha256.New()
	hasher.Write(objBytes)
	sha256Hex := hex.EncodeToString(hasher.Sum(nil))

	// Read and parse manifest.yaml
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest.yaml: %w", err)
	}

	// Canonicalize line endings to pure LF (\n) to prevent hybrid newline generation
	manifestBytes = bytes.ReplaceAll(manifestBytes, []byte("\r\n"), []byte("\n"))

	moduleName, currentVersion, err := parseManifestDoc(manifestBytes)
	if err != nil {
		return fmt.Errorf("failed to parse manifest details: %w", err)
	}

	// Bump version if requested
	if autoBump != "" {
		newVersion, err := bumpVersion(currentVersion, autoBump)
		if err != nil {
			return fmt.Errorf("failed to bump version: %w", err)
		}
		manifestBytes = updateVersion(manifestBytes, newVersion)
		fmt.Printf("Auto-bumped version: %s -> %s\n", currentVersion, newVersion)
	}

	// Update the sha256 in manifest.yaml
	updatedManifestBytes := updateSHA256(manifestBytes, sha256Hex)

	// Write the updated manifest.yaml back to the source directory
	err = os.WriteFile(manifestPath, updatedManifestBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write updated manifest back to source: %w", err)
	}

	// Create gzip-compressed tarball containing manifest.yaml, program.o, and manifest.sig (when signed)
	escapedName := strings.ReplaceAll(moduleName, "/", "-")
	epmPath := filepath.Join(outDir, escapedName+".epm")

	filesToPack := map[string][]byte{
		"manifest.yaml": updatedManifestBytes,
		"program.o":     objBytes,
	}
	if !unsigned {
		sigBytes := ed25519.Sign(privKey, updatedManifestBytes)
		tempSigPath := filepath.Join(tempDir, "manifest.sig")
		if err := os.WriteFile(tempSigPath, sigBytes, 0644); err != nil {
			return fmt.Errorf("failed to write manifest.sig: %w", err)
		}
		filesToPack["manifest.sig"] = sigBytes
	}

	if err := createTarGz(epmPath, filesToPack); err != nil {
		return fmt.Errorf("failed to create epm archive: %w", err)
	}

	if unsigned {
		fmt.Printf("Successfully packaged (unsigned): %s -> %s\n", moduleName, epmPath)
	} else {
		fmt.Printf("Successfully packaged: %s -> %s\n", moduleName, epmPath)
	}
	return nil
}

// parseManifestDoc uses proper YAML unmarshaling to extract the top-level 'name' and 'version',
// eliminating the risk of matching nested 'name:' keys (Finding #7).
func parseManifestDoc(manifestContent []byte) (string, string, error) {
	var doc manifestDoc
	if err := yaml.Unmarshal(manifestContent, &doc); err != nil {
		return "", "", fmt.Errorf("failed to parse manifest YAML: %w", err)
	}
	if doc.Name == "" {
		return "", "", fmt.Errorf("module name not found in manifest")
	}
	return doc.Name, doc.Version, nil
}

func bumpVersion(currentVersion string, bumpType string) (string, error) {
	parts := strings.Split(currentVersion, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid semantic version format (expected X.Y.Z): %s", currentVersion)
	}

	var major, minor, patch int
	fmt.Sscanf(parts[0], "%d", &major)
	fmt.Sscanf(parts[1], "%d", &minor)
	fmt.Sscanf(parts[2], "%d", &patch)

	switch strings.ToLower(bumpType) {
	case "major":
		major++
		minor = 0
		patch = 0
	case "minor":
		minor++
		patch = 0
	case "patch":
		patch++
	default:
		return "", fmt.Errorf("invalid auto-bump type (expected patch, minor, or major): %s", bumpType)
	}

	return fmt.Sprintf("%d.%d.%d", major, minor, patch), nil
}

// updateVersion safely modifies the version field in the yaml
func updateVersion(manifestContent []byte, newVersion string) []byte {
	var root yaml.Node
	if err := yaml.Unmarshal(manifestContent, &root); err != nil {
		return manifestContent // fallback
	}
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		mapping := root.Content[0]
		for i := 0; i < len(mapping.Content)-1; i += 2 {
			if mapping.Content[i].Value == "version" {
				mapping.Content[i+1].Value = newVersion
				break
			}
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err == nil {
		return buf.Bytes()
	}
	return manifestContent // fallback
}

// updateSHA256 uses yaml.Node to preserve the original YAML structure, comments,
// and key ordering while only updating the sha256 value (Finding #6).
func updateSHA256(manifestContent []byte, sha256Hex string) []byte {
	var root yaml.Node
	if err := yaml.Unmarshal(manifestContent, &root); err != nil {
		// Fallback: append sha256 if YAML is unparseable
		return append(manifestContent, []byte("sha256: "+sha256Hex+"\n")...)
	}
	// Walk the top-level mapping to find or insert sha256
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		mapping := root.Content[0]
		found := false
		for i := 0; i < len(mapping.Content)-1; i += 2 {
			if mapping.Content[i].Value == "sha256" {
				mapping.Content[i+1].Value = sha256Hex
				mapping.Content[i+1].Tag = "!!str"
				mapping.Content[i+1].Style = 0
				found = true
				break
			}
		}
		if !found {
			mapping.Content = append(mapping.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Value: "sha256"},
				&yaml.Node{Kind: yaml.ScalarNode, Value: sha256Hex},
			)
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		// Fallback: return original with appended sha256
		return append(manifestContent, []byte("sha256: "+sha256Hex+"\n")...)
	}
	enc.Close()
	return buf.Bytes()
}

// createTarGz builds a gzip-compressed tarball. Writers are closed explicitly
// in reverse order to propagate flush/trailer errors (Finding #3).
func createTarGz(outputPath string, files map[string][]byte) (retErr error) {
	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := outFile.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("failed to close output file: %w", cerr)
		}
		// If any error occurred, clean up the potentially corrupt file
		if retErr != nil {
			os.Remove(outputPath)
		}
	}()

	gw := gzip.NewWriter(outFile)
	tw := tar.NewWriter(gw)

	orderedNames := []string{"manifest.yaml", "manifest.sig", "program.o"}
	for _, name := range orderedNames {
		content, ok := files[name]
		if !ok {
			if name == "manifest.sig" {
				continue // Unsigned packages intentionally omit manifest.sig
			}
			return fmt.Errorf("missing required file %s in packaging map", name)
		}

		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(content); err != nil {
			return err
		}
	}

	// Explicit close in reverse order to flush data and catch errors
	if err := tw.Close(); err != nil {
		return fmt.Errorf("failed to finalize tar archive: %w", err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("failed to finalize gzip compression: %w", err)
	}
	return nil
}
