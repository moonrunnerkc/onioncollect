VM := node1
PYTHON := .venv/bin/python
STAGE := /tmp/onioncollect-stage
APP := /home/crawler/app
DISK := $(HOME)/.lima/$(VM)/disk
TESTONION_VM := testonion-vm
TESTONION_STAGE := /tmp/testonion-stage
PRUNE_CONFIGS ?= 0

.PHONY: venv test vm provision install deploy shell checklist leak-test crawl-capture crawl-full snapshot \
	testonion-vm testonion testonion-credentials writeup-check writeup-capture

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

# The guest half is deploy/install.sh, as root: both app copies, the systemd units, the configs (never deleting
# a guest config unless PRUNE_CONFIGS=1 and you type yes), and a new deploy stamp.
install: vm
	limactl shell $(VM) sh -c 'rm -rf $(STAGE) && mkdir -p $(STAGE)'
	limactl copy -r onioncollect tests tools deploy $(VM):$(STAGE)/
	@# The two safety files are never committed. When this checkout has one, it replaces the guest's copy.
	for f in safety-patterns.txt exclusions.txt; do \
		if [ -f $$f ]; then \
			limactl copy $$f $(VM):$(STAGE)/ && \
			limactl shell $(VM) sudo sh -c "install -m 600 -o crawler -g crawler $(STAGE)/$$f /home/crawler/ && rm $(STAGE)/$$f" || exit 1; \
		fi; \
	done
	if [ -d configs ]; then limactl copy -r configs $(VM):$(STAGE)/; fi
	limactl shell $(VM) sudo PRUNE_CONFIGS=$(PRUNE_CONFIGS) bash $(STAGE)/deploy/install.sh $(STAGE)

# Ends with the leak tests, which record the new stamp, so a fresh deploy never blocks the crawl. The crawl
# timer starts only if they pass.
deploy: install
	limactl shell $(VM) sudo bash /opt/onioncollect/app/tests/live/leak_test.sh
	limactl shell $(VM) sudo systemctl start onioncollect-crawl.timer

shell: vm
	limactl shell $(VM) sudo -iu crawler

# Root runs these from the admin-owned staging copy, never from the crawler-writable app dir.
checklist: install
	limactl shell $(VM) sudo bash $(STAGE)/tests/live/checklist.sh; guest=$$?; \
	if fdesetup status | grep -q "FileVault is On"; then echo "PASS  host FileVault on"; else echo "FAIL  host FileVault on"; guest=1; fi; \
	if [ -f $(DISK).snapshot ]; then echo "PASS  snapshot $(DISK).snapshot"; else echo "FAIL  no snapshot (make snapshot)"; guest=1; fi; \
	exit $$guest

# The installed copy, as the daily timer runs it. After a code change, make deploy instead.
leak-test: vm
	limactl shell $(VM) sudo bash /opt/onioncollect/app/tests/live/leak_test.sh

# Build step 8: one worker on one Tor instance for CRAWL_SECONDS under the leak test 3 capture.
crawl-capture: deploy
	limactl shell $(VM) sudo CRAWL_SECONDS=$(or $(CRAWL_SECONDS),600) bash $(STAGE)/tests/live/crawl_capture.sh

# Build step 9: every Tor instance at workers_per_instance, same capture, plus each instance's stream peak.
crawl-full: deploy
	limactl shell $(VM) sudo CRAWL_SCOPE=full CRAWL_SECONDS=$(or $(CRAWL_SECONDS),600) bash $(STAGE)/tests/live/crawl_capture.sh

# Lima's vz driver has no snapshots, so this is an APFS clone of the stopped disk.
# Roll back with: limactl stop node1 && cp -c ~/.lima/node1/disk.snapshot ~/.lima/node1/disk
snapshot:
	limactl stop $(VM)
	cp -c $(DISK) $(DISK).snapshot
	limactl start --tty=false $(VM)

# Section 15's self-hosted onion, on its own VM. Prints the onion address it serves.
testonion-vm:
	limactl list -q | grep -qx $(TESTONION_VM) || limactl create --name=$(TESTONION_VM) --tty=false testonion/lima.yaml
	limactl list -f '{{.Status}}' $(TESTONION_VM) | grep -qx Running || limactl start --tty=false $(TESTONION_VM)

testonion: testonion-vm
	limactl shell $(TESTONION_VM) sh -c 'rm -rf $(TESTONION_STAGE) && mkdir -p $(TESTONION_STAGE)'
	limactl copy testonion/app.py testonion/torrc testonion/testonion.service testonion/setup.sh \
		$(TESTONION_VM):$(TESTONION_STAGE)/
	limactl shell $(TESTONION_VM) sudo bash $(TESTONION_STAGE)/setup.sh $(TESTONION_STAGE)

# The credentials go from the test onion's VM to the crawler's through this pipe only: never the host's disk,
# never a terminal. Crawler-owned and mode 600 on arrival, outside the configs and the repo.
testonion-credentials: vm testonion-vm
	limactl shell $(TESTONION_VM) sudo cat /etc/testonion/credentials | limactl shell $(VM) sudo sh -c \
		'install -d -m 750 -o root -g crawler /etc/onioncollect && umask 077 && \
		cat > /etc/onioncollect/testonion.env && chown crawler:crawler /etc/onioncollect/testonion.env'

# Lists every [PASTE: ...] marker left in the write-up; fails while any remains.
writeup-check:
	$(PYTHON) tools/writeup_check.py docs/writeup.md README.md

# As the analyst in the guest: one bundle of the write-up's evidence under /home/analyst/writeup-capture,
# stripped of the testonion address, the credential values and host IPs before anything is written.
writeup-capture: vm
	limactl shell $(VM) sudo systemctl start --wait onioncollect-capture.service
	limactl shell $(VM) sudo -u analyst sh -c 'ls -1d /home/analyst/writeup-capture/* | tail -1'
