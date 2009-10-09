mod_syslog.la: mod_syslog.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_syslog.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_syslog.la
