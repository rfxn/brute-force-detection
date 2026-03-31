#!/usr/bin/make -f
#
# BFD Package Build Orchestration
# Builds RPM and DEB packages from the project source tree.
#
# Targets:
#   make source           - Create source tarball
#   make rpm              - Build RPM (native rpmbuild)
#   make deb              - Build DEB (native dpkg-buildpackage)
#   make rpm-el7          - Build el7 RPM in Docker (CentOS 7)
#   make rpm-el9          - Build el8/el9/el10 RPM in Docker (Rocky 9)
#   make deb-debian12     - Build DEB in Docker (Debian 12)
#   make test-rpm-rocky9  - Test RPM install in Docker (Rocky 9)
#   make test-deb-debian12 - Test DEB install in Docker (Debian 12)
#   make clean            - Remove build artifacts
#

PROJDIR := $(realpath $(dir $(MAKEFILE_LIST))/..)
VERSION := $(shell grep '^V=' $(PROJDIR)/files/bfd | head -1 | sed 's/V="//;s/"//')
NAME    := bfd
TARBALL := $(NAME)-$(VERSION).tar.gz
BUILDDIR := $(CURDIR)/build

.PHONY: source rpm deb clean rpm-el7 rpm-el9 deb-debian12 \
        test-rpm-rocky9 test-deb-debian12

# --- Source tarball ---

source: $(BUILDDIR)/$(TARBALL)

# Use git archive when available (native builds), fall back to tar
$(BUILDDIR)/$(TARBALL):
	mkdir -p $(BUILDDIR)
	@if command -v git >/dev/null 2>&1 && [ -d "$(PROJDIR)/.git" ]; then \
	    cd $(PROJDIR) && \
	    git archive --format=tar.gz --prefix=$(NAME)-$(VERSION)/ \
	        -o $(BUILDDIR)/$(TARBALL) HEAD; \
	else \
	    cd $(PROJDIR) && \
	    tar czf $(BUILDDIR)/$(TARBALL) \
	        --transform 's,^\./,$(NAME)-$(VERSION)/,' \
	        --exclude='.git' --exclude='tests' \
	        --exclude='pkg' --exclude='docs' \
	        --exclude='audit-output' --exclude='.github' \
	        --exclude='.rdf' --exclude='.claude' \
	        --exclude='CLAUDE.md' --exclude='PLAN*.md' \
	        --exclude='AUDIT.md' --exclude='MEMORY.md' \
	        --exclude='REGR.md' --exclude='PRESSURE.md' \
	        --exclude='.dockerignore' --exclude='.gitattributes' \
	        . ; \
	fi

# --- Native RPM build ---

rpm: $(BUILDDIR)/$(TARBALL)
	mkdir -p $(BUILDDIR)/rpmbuild/{SOURCES,SPECS,BUILD,RPMS,SRPMS}
	cp $(BUILDDIR)/$(TARBALL) $(BUILDDIR)/rpmbuild/SOURCES/
	cp $(CURDIR)/rpm/bfd.spec $(BUILDDIR)/rpmbuild/SPECS/
	rpmbuild -bb \
	    --define "_topdir $(BUILDDIR)/rpmbuild" \
	    $(BUILDDIR)/rpmbuild/SPECS/bfd.spec
	@echo "RPM(s) built in $(BUILDDIR)/rpmbuild/RPMS/noarch/"

# --- Native DEB build ---

deb: $(BUILDDIR)/$(TARBALL)
	mkdir -p $(BUILDDIR)/deb-build
	cd $(BUILDDIR)/deb-build && \
	tar xzf $(BUILDDIR)/$(TARBALL) && \
	cp -a $(CURDIR)/deb/debian $(BUILDDIR)/deb-build/$(NAME)-$(VERSION)/ && \
	cd $(NAME)-$(VERSION) && \
	dpkg-buildpackage -us -uc -b
	@echo "DEB built in $(BUILDDIR)/deb-build/"

# --- Docker RPM builds ---

rpm-el7:
	docker build -t bfd-rpm-el7 -f $(CURDIR)/docker/Dockerfile.rpm-el7 $(PROJDIR)
	mkdir -p $(BUILDDIR)/rpms
	docker run --rm -v $(BUILDDIR)/rpms:/output bfd-rpm-el7

rpm-el9:
	docker build -t bfd-rpm-el9 -f $(CURDIR)/docker/Dockerfile.rpm-el9 $(PROJDIR)
	mkdir -p $(BUILDDIR)/rpms
	docker run --rm -v $(BUILDDIR)/rpms:/output bfd-rpm-el9

# --- Docker DEB build ---

deb-debian12:
	docker build -t bfd-deb -f $(CURDIR)/docker/Dockerfile.deb $(PROJDIR)
	mkdir -p $(BUILDDIR)/debs
	docker run --rm -v $(BUILDDIR)/debs:/output bfd-deb

# --- Package install tests ---

test-rpm-rocky9: rpm-el9
	cp $(CURDIR)/test/test-pkg-install.sh $(BUILDDIR)/rpms/
	docker build -t bfd-test-rpm-rocky9 \
	    -f $(CURDIR)/test/Dockerfile.test-rpm-rocky9 $(BUILDDIR)/rpms
	docker run --rm --privileged bfd-test-rpm-rocky9

test-deb-debian12: deb-debian12
	cp $(CURDIR)/test/test-pkg-install.sh $(BUILDDIR)/debs/
	docker build -t bfd-test-deb-debian12 \
	    -f $(CURDIR)/test/Dockerfile.test-deb-debian12 $(BUILDDIR)/debs
	docker run --rm --privileged bfd-test-deb-debian12

# --- Clean ---

clean:
	rm -rf $(BUILDDIR)
