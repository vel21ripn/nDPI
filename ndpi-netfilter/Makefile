all:
	$(MAKE) -C ipt
	$(MAKE) -C src
incl:	src/xt_ndpi.h


src/xt_ndpi.h: ../src/include/ndpi_protocol_ids.h src/xt_ndpi.h.src 
	perl ./gen_protocols.pl $@ $^ 

modules_install:
	$(MAKE) -C src modules_install
install:
	$(MAKE) -C ipt install
clean:
	$(MAKE) -C src clean
	$(MAKE) -C ipt clean
distclean:
	$(MAKE) clean
	$(MAKE) -C src distclean
