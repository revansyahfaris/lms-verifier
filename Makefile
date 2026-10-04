# Pemakaian:
#   make test            -> semua testbench (tb/*.f) + unit test Python
#   make sim TB=smoke    -> satu testbench, simpan waveform di build/<TB>.vcd
#   make clean
IVERILOG ?= iverilog
VVP      ?= vvp
PYTHON   ?= python3
FLAGS    := -g2012 -Wall -I rtl/common

TBS := $(basename $(notdir $(wildcard tb/*.f)))

.PHONY: test sim rtl-test py-test clean

test: rtl-test py-test

rtl-test:
	@mkdir -p build
	@fail=0; for t in $(TBS); do \
	  printf '%-24s' "$$t"; \
	  $(IVERILOG) $(FLAGS) -o build/$$t.vvp -c tb/$$t.f >build/$$t.log 2>&1 && \
	  $(VVP) -n build/$$t.vvp >>build/$$t.log 2>&1; \
	  if grep -q 'TEST FAILED' build/$$t.log || ! grep -q 'TEST PASSED' build/$$t.log; then \
	    echo "GAGAL  (lihat build/$$t.log)"; fail=1; \
	  else echo "lolos"; fi; \
	done; exit $$fail

sim:
	@test -n "$(TB)" || (echo "Pakai: make sim TB=<nama>"; exit 1)
	@mkdir -p build
	$(IVERILOG) $(FLAGS) -DDUMP_VCD -o build/$(TB).vvp -c tb/$(TB).f
	$(VVP) -n build/$(TB).vvp

py-test:
	@$(PYTHON) -m pytest -q python/tests

clean:
	rm -rf build
