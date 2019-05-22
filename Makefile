MODULES = pg_restrict

REGRESS_OPTS = --temp-instance=./tmp_check --temp-config=./pg_restrict.conf
REGRESS = pg_restrict
# Disabled because these tests require "shared_preload_libraries=pg_restrict",
# which typical installcheck users do not have.
NO_INSTALLCHECK = 1

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

astyle:
	astyle --style=bsd --indent=force-tab=4 --indent-switches --pad-oper --align-pointer=name --align-reference=name --remove-brackets --max-code-length=80 --break-after-logical --suffix=none --lineend=linux pg_restrict.c

# But it can nonetheless be very helpful to run tests on preexisting
# installation, allow to do so, but only if requested explicitly.
check-force:
	$(pg_regress_installcheck) $(REGRESS_OPTS) $(REGRESS)
