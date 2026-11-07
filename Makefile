VM := node1
PYTHON := .venv/bin/python
STAGE := /tmp/onioncrawl-stage
APP := /home/crawler/app
DISK := $(HOME)/.lima/$(VM)/disk

.PHONY: venv test vm provision deploy shell checklist leak-test crawl-capture snapshot

venv:
	python3.13 -m venv .venv
	.venv/bin/pip install --require-hashes -r requirements.txt

test:
	$(PYTHON) -m unittest discover -s tests -t .

vm:
	limactl list -q | grep -qx $(VM) || limactl create --name=$(VM) --tty=false provision/lima.yaml
	limactl list -f '{{.Status}}' $(VM) | grep -qx Running || limactl start --tty=false $(VM)

provision: vm
	limactl shell $(VM) sh -c 'rm -rf $(STAGE) && mkdir -p $(STAGE)'
	limactl copy provision/provision.sh provision/torrc.template requirements.txt $(VM):$(STAGE)/
	limactl shell $(VM) sudo sh -c 'install -m 700 $(STAGE)/provision.sh /etc/onioncrawl/ && \
		install -m 644 $(STAGE)/torrc.template $(STAGE)/requirements.txt /etc/onioncrawl/ && \
		/etc/onioncrawl/provision.sh'

deploy: vm
	limactl shell $(VM) sh -c 'rm -rf $(STAGE) && mkdir -p $(STAGE)'
	limactl copy -r onioncrawl tests $(VM):$(STAGE)/
	limactl shell $(VM) sudo sh -c 'rm -rf $(APP) && install -d -m 700 -o crawler -g crawler $(APP) && \
		cp -r $(STAGE)/onioncrawl $(STAGE)/tests $(APP)/ && find $(APP) -name __pycache__ -prune -exec rm -rf {} + ; \
		chown -R crawler:crawler $(APP)'
	@# The safety pattern list is not committed. When this checkout has one, it replaces the guest's copy.
	if [ -f safety-patterns.txt ]; then \
		limactl copy safety-patterns.txt $(VM):$(STAGE)/ && \
		limactl shell $(VM) sudo sh -c "install -m 600 -o crawler -g crawler $(STAGE)/safety-patterns.txt /home/crawler/ && rm $(STAGE)/safety-patterns.txt"; \
	fi

shell: vm
	limactl shell $(VM) sudo -iu crawler

# Root runs these from the admin-owned staging copy, never from the crawler-writable app dir.
checklist: deploy
	limactl shell $(VM) sudo bash $(STAGE)/tests/live/checklist.sh; guest=$$?; \
	if fdesetup status | grep -q "FileVault is On"; then echo "PASS  host FileVault on"; else echo "FAIL  host FileVault on"; guest=1; fi; \
	if [ -f $(DISK).snapshot ]; then echo "PASS  snapshot $(DISK).snapshot"; else echo "FAIL  no snapshot (make snapshot)"; guest=1; fi; \
	exit $$guest

leak-test: deploy
	limactl shell $(VM) sudo bash $(STAGE)/tests/live/leak_test.sh

# Build step 8: one worker on one Tor instance for CRAWL_SECONDS under the leak test 3 capture.
crawl-capture: deploy
	limactl shell $(VM) sudo CRAWL_SECONDS=$(or $(CRAWL_SECONDS),600) bash $(STAGE)/tests/live/crawl_capture.sh

# Lima's vz driver has no snapshots, so this is an APFS clone of the stopped disk.
# Roll back with: limactl stop node1 && cp -c ~/.lima/node1/disk.snapshot ~/.lima/node1/disk
snapshot:
	limactl stop $(VM)
	cp -c $(DISK) $(DISK).snapshot
	limactl start --tty=false $(VM)
