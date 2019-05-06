MODULES = pg_restrict
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

astyle:
	astyle --style=bsd --indent=force-tab=4 --indent-switches --pad-oper --align-pointer=name --align-reference=name --remove-brackets --max-code-length=80 --break-after-logical --suffix=none --lineend=linux pg_restrict.c
