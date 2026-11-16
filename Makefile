.PHONY: all clean build build-unsigned registry-data

all: build registry-data

build:
	go build -o eprobe-pack cmd/eprobe-pack/main.go

build-unsigned: build
	@mkdir -p dist
	@set -e; find modules -mindepth 2 -maxdepth 2 -type d | sort | while read -r dir; do \
		if [ -f "$$dir/manifest.yaml" ]; then \
			./eprobe-pack --unsigned --dir "$$dir" --output-dir dist; \
		fi; \
	done

registry-data: build
	@if [ -z "$$EPROBE_SIGNING_KEY" ]; then \
		echo "Error: EPROBE_SIGNING_KEY environment variable must be set." >&2; \
		exit 1; \
	fi
	@set -e; find modules -mindepth 2 -maxdepth 2 -type d | sort | while read -r dir; do \
		if [ -f "$$dir/manifest.yaml" ]; then \
			./eprobe-pack --dir "$$dir" --output-dir registry-data --auto-bump=patch; \
		fi; \
	done

clean:
	rm -rf eprobe-pack registry-data/ dist/
