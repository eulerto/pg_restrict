/*----------------------------------------------------------------------
 *
 * pg_restrict - restricts commands to master roles
 *
 *
 * Copyright (c) 2019, Euler Taveira
 *
 *----------------------------------------------------------------------
 */

#include "postgres.h"
#include "miscadmin.h"
#include "nodes/pg_list.h"
#include "parser/scansup.h"
#include "tcop/utility.h"
#include "utils/guc.h"
#include "utils/memutils.h"

#define	PGR_DEFAULT_MASTER_ROLES		"postgres"
#define	PGR_DEFAULT_NONREMOVABLE_DBS	"postgres, template1, template0"
#define	PGR_DEFAULT_NONREMOVABLE_ROLES	"postgres"

PG_MODULE_MAGIC;

#if PG_VERSION_NUM >= 90400
/* whether to restrict ALTER SYSTEM */
bool		alter_system;
#endif
/* whether to restrict ALTER TABLE */
bool		alter_table;
/* wheter to restrict COPY ... PROGRAM */
bool		copy_program;
/* list of master roles (have no restrictions) */
char		*masterroles = PGR_DEFAULT_MASTER_ROLES;
/* whether to restrict DROP some databases */
char		*nonremovabledbs = PGR_DEFAULT_NONREMOVABLE_DBS;
/* whether to restrict DROP some roles */
char		*nonremovableroles = PGR_DEFAULT_NONREMOVABLE_ROLES;

static List		*master_roles = NIL;
static List		*nonremovable_databases = NIL;
static List		*nonremovable_roles = NIL;


void _PG_init(void);
void _PG_fini(void);

/* Saved hook value in case of unload */
static ProcessUtility_hook_type prev_ProcessUtility = NULL;

static bool check_nonremovable_databases(char **newval, void **extra,
		GucSource source);
static void assign_nonremovable_databases(const char *newval, void *extra);
static bool check_nonremovable_roles(char **newval, void **extra,
									 GucSource source);
static void assign_nonremovable_roles(const char *newval, void *extra);
static bool check_master_roles(char **newval, void **extra,
							   GucSource source);
static void assign_master_roles(const char *newval, void *extra);

#if PG_VERSION_NUM >= 130000
static void pgr_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
							   ProcessUtilityContext context, ParamListInfo params, QueryEnvironment *queryEnv,
							   DestReceiver *dest, QueryCompletion *qc);
#elif PG_VERSION_NUM >= 100000
static void pgr_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
							   ProcessUtilityContext context, ParamListInfo params, QueryEnvironment *queryEnv,
							   DestReceiver *dest, char *completionTag);
#else
static void pgr_ProcessUtility(Node *pstmt, const char *queryString,
							   ProcessUtilityContext context, ParamListInfo params,
							   DestReceiver *dest, char *completionTag);
#endif
static bool split_string_into_list(char *rawstring, char separator,
								   List **namelist);

void
_PG_init(void)
{
	/*
	 * Define (or redefine) custom GUC variable.
	 */
#if PG_VERSION_NUM >= 90400
	DefineCustomBoolVariable("pg_restrict.alter_system",
							 "Roles cannot use ALTER SYSTEM unless it is listed as master role.",
							 NULL,
							 &alter_system,
							 false,
							 PGC_SIGHUP, 0,
							 NULL,
							 NULL,
							 NULL);
#endif

	DefineCustomBoolVariable("pg_restrict.alter_table",
							 "Roles (even superusers) cannot use ALTER TABLE unless it is listed as master role.",
							 NULL,
							 &alter_table,
							 false,
							 PGC_SIGHUP, 0,
							 NULL,
							 NULL,
							 NULL);
	
	DefineCustomBoolVariable("pg_restrict.copy_program",
							 "Roles (even superusers) cannot use COPY ... PROGRAM unless it is listed as master role.",
							 NULL,
							 &copy_program,
							 false,
							 PGC_SIGHUP, 0,
							 NULL,
							 NULL,
							 NULL);
	
	DefineCustomStringVariable("pg_restrict.master_roles",
							   "Roles that are allowed to execute restricted commands.",
							   NULL,
							   &masterroles,
							   PGR_DEFAULT_MASTER_ROLES,
							   PGC_POSTMASTER, 0,
							   check_master_roles,
							   assign_master_roles,
							   NULL);

	DefineCustomStringVariable("pg_restrict.nonremovable_databases",
							   "Roles (even superusers) cannot drop these databases unless it is listed as master role.",
							   NULL,
							   &nonremovabledbs,
							   PGR_DEFAULT_NONREMOVABLE_DBS,
							   PGC_SIGHUP, 0,
							   check_nonremovable_databases,
							   assign_nonremovable_databases,
							   NULL);

	DefineCustomStringVariable("pg_restrict.nonremovable_roles",
							   "Roles (even superusers) cannot drop these roles unless it is listed as master role.",
							   NULL,
							   &nonremovableroles,
							   PGR_DEFAULT_NONREMOVABLE_ROLES,
							   PGC_SIGHUP, 0,
							   check_nonremovable_roles,
							   assign_nonremovable_roles,
							   NULL);

	EmitWarningsOnPlaceholders("pg_restrict");

	/*
	 * Install hook.
	 */
	prev_ProcessUtility = ProcessUtility_hook;
	ProcessUtility_hook = pgr_ProcessUtility;
}

void
_PG_fini(void)
{
	/*
	 * Uninstall hook.
	 */
	ProcessUtility_hook = prev_ProcessUtility;
}

/*
 * ProcessUtility hook
 */
#if PG_VERSION_NUM >= 130000
static void
pgr_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
				   ProcessUtilityContext context, ParamListInfo params, QueryEnvironment *queryEnv,
				   DestReceiver *dest, QueryCompletion *qc)
{
	Node	*pst = (Node *) pstmt->utilityStmt;
#elif PG_VERSION_NUM >= 100000
static void
pgr_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
				   ProcessUtilityContext context, ParamListInfo params, QueryEnvironment *queryEnv,
				   DestReceiver *dest, char *completionTag)
{
	Node	*pst = (Node *) pstmt->utilityStmt;
#else
static void
pgr_ProcessUtility(Node *pst, const char *queryString,
				   ProcessUtilityContext context, ParamListInfo params,
				   DestReceiver *dest, char *completionTag)
{
#endif

#if PG_VERSION_NUM >= 90500
	char		*current_rolename = GetUserNameFromId(GetUserId(), false);
#else
	char		*current_rolename = GetUserNameFromId(GetUserId());
#endif

	if (IsA(pst, DropdbStmt))
	{
		DropdbStmt	*stmt = (DropdbStmt *) pst;
		ListCell	*lc;

		/*
		 * Only master roles can drop databases listed as non-removable databases
		 */
		foreach(lc, nonremovable_databases)
		{
			if (strcmp(lfirst(lc), stmt->dbname) == 0)
			{
				bool		is_master = false;
				ListCell	*tc;

				foreach(tc, master_roles)
				{
					if (strcmp(lfirst(tc), current_rolename) == 0)
					{
						is_master = true;
						break;
					}
				}

				if (!is_master)
					ereport(ERROR,
							(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
							 errmsg("cannot drop database \"%s\"", stmt->dbname)));
			}
		}
	}
	else if (IsA(pst, DropRoleStmt))
	{
		DropRoleStmt	*stmt = (DropRoleStmt *) pst;
		ListCell		*lc;

		foreach(lc, stmt->roles)
		{
#if PG_VERSION_NUM >= 90500
			RoleSpec	*rolspec = lfirst(lc);
			char		*dropped_role = rolspec->rolename;
#else
			const char	*dropped_role = strVal(lfirst(lc));
#endif
			ListCell	*tc;

			/*
			 * Only master roles can drop roles listed as non-removable roles
			 */
			foreach(tc, nonremovable_roles)
			{
				if (strcmp(lfirst(tc), dropped_role) == 0)
				{
					bool		is_master = false;
					ListCell	*ms;

					foreach(ms, master_roles)
					{
						if (strcmp(lfirst(ms), current_rolename) == 0)
						{
							is_master = true;
							break;
						}
					}

					if (!is_master)
						ereport(ERROR,
								(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
								 errmsg("cannot drop role \"%s\"", dropped_role)));
				}
			}
		}
	}
#if PG_VERSION_NUM >= 90400
	else if (IsA(pst, AlterSystemStmt) && alter_system)
	{
		bool		is_master = false;
		ListCell	*lc;

		foreach(lc, master_roles)
		{
			if (strcmp(lfirst(lc), current_rolename) == 0)
			{
				is_master = true;
				break;
			}
		}

		/*
		 * Only master roles can execute ALTER SYSTEM
		 */
		if (!is_master)
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("cannot execute ALTER SYSTEM")));
	}
#endif	/* AlterSystemStmt >= 9.4 */
	else if (IsA(pst, CopyStmt) && copy_program)
	{
		CopyStmt	*stmt = (CopyStmt *) pst;
		bool		is_master = false;
		ListCell	*lc;

		/* COPY ... PROGRAM is new in 9.3 */
		if (stmt->is_program)
		{
			foreach(lc, master_roles)
			{
				if (strcmp(lfirst(lc), current_rolename) == 0)
				{
					is_master = true;
					break;
				}
			}

			/*
			 * Only master roles can execute COPY ... PROGRAM
			 */
			if (!is_master)
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("cannot execute COPY ... PROGRAM")));
		}
	}

#if PG_VERSION_NUM >= 100000
	else if (IsA(pstmt->utilityStmt, AlterTableStmt) && alter_table)
	{
		AlterTableStmt	*stmt = (AlterTableStmt *) pstmt->utilityStmt;
#else
	else if (IsA(pstmt, AlterTableStmt) && alter_table)
	{
		AlterTableStmt	*stmt = (AlterTableStmt *) pstmt;
#endif
		bool		is_master = false;
		ListCell	*lc;

			foreach(lc, master_roles)
			{
				if (strcmp(lfirst(lc), current_rolename) == 0)
				{
					is_master = true;
					break;
				}
			}

			/*
			 * Only master roles can execute ALTER TABLE
			 */
			if (!is_master)
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("cannot execute ALTER TABLE")));
	}
	/*
	 * Fallback to normal process, be it the previous hook loaded
	 * or the in-core code path if the previous hook does not exist.
	 */
#if PG_VERSION_NUM >= 130000
	if (prev_ProcessUtility)
		prev_ProcessUtility(pstmt, queryString,
							context, params, queryEnv,
							dest, qc);
	else
		standard_ProcessUtility(pstmt, queryString,
								context, params, queryEnv,
								dest, qc);
#elif PG_VERSION_NUM >= 100000
	if (prev_ProcessUtility)
		prev_ProcessUtility(pstmt, queryString,
							context, params, queryEnv,
							dest, completionTag);
	else
		standard_ProcessUtility(pstmt, queryString,
								context, params, queryEnv,
								dest, completionTag);
#else
	if (prev_ProcessUtility)
		prev_ProcessUtility(pst, queryString,
							context, params,
							dest, completionTag);
	else
		standard_ProcessUtility(pst, queryString,
								context, params,
								dest, completionTag);
#endif
}

static bool
check_nonremovable_databases(char **newval, void **extra, GucSource source)
{
	char			*rawstring;
	List			*newnrdbs = NIL;
	List			*ltmp;
	ListCell		*lc;
	MemoryContext	oldctx;

	rawstring = pstrdup(*newval);

	if (!split_string_into_list(rawstring, ',', &ltmp))
	{
		/* syntax error in list */
		GUC_check_errdetail("List syntax is invalid.");
		pfree(rawstring);
		return false;
	}

	oldctx = MemoryContextSwitchTo(TopMemoryContext);

	foreach(lc, ltmp)
	{
		char	*t = pstrdup((char *) lfirst(lc));
		newnrdbs = lappend(newnrdbs, t);
	}

	list_free(nonremovable_databases);
	nonremovable_databases = newnrdbs;

	MemoryContextSwitchTo(oldctx);

	pfree(rawstring);

	return true;
}

static void
assign_nonremovable_databases(const char *newval, void *extra)
{
}

static bool
check_nonremovable_roles(char **newval, void **extra, GucSource source)
{
	char			*rawstring;
	List			*newnrroles = NIL;
	List			*ltmp;
	ListCell		*lc;
	MemoryContext	oldctx;

	rawstring = pstrdup(*newval);

	if (!split_string_into_list(rawstring, ',', &ltmp))
	{
		/* syntax error in list */
		GUC_check_errdetail("List syntax is invalid.");
		pfree(rawstring);
		return false;
	}

	oldctx = MemoryContextSwitchTo(TopMemoryContext);

	foreach(lc, ltmp)
	{
		char	*t = pstrdup((char *) lfirst(lc));
		newnrroles = lappend(newnrroles, t);
	}

	list_free(nonremovable_roles);
	nonremovable_roles = newnrroles;

	MemoryContextSwitchTo(oldctx);

	pfree(rawstring);

	return true;
}

static void
assign_nonremovable_roles(const char *newval, void *extra)
{
}

static bool
check_master_roles(char **newval, void **extra, GucSource source)
{
	char			*rawstring;
	List			*newmasterroles = NIL;
	List			*ltmp;
	ListCell		*lc;
	MemoryContext	oldctx;

	rawstring = pstrdup(*newval);

	if (!split_string_into_list(rawstring, ',', &ltmp))
	{
		/* syntax error in list */
		GUC_check_errdetail("List syntax is invalid.");
		pfree(rawstring);
		return false;
	}

	oldctx = MemoryContextSwitchTo(TopMemoryContext);

	foreach(lc, ltmp)
	{
		char	*t = pstrdup((char *) lfirst(lc));
		newmasterroles = lappend(newmasterroles, t);
	}

	list_free(master_roles);
	master_roles = newmasterroles;

	MemoryContextSwitchTo(oldctx);

	pfree(rawstring);

	return true;
}

static void
assign_master_roles(const char *newval, void *extra)
{
}

/*
 * This function is a copy of split_string_into_list. It is here because it was
 * introduced as a bugfix. 9.3.24, 9,4,19, 9.5.14, 9.6.10, and 10.5 already
 * contains it but prior minor versions don't. Since we want to support stable
 * versions, it is included here as is.
 */
static bool
split_string_into_list(char *rawstring, char separator,
					   List **namelist)
{
	char	   *nextp = rawstring;
	bool		done = false;

	*namelist = NIL;

	while (scanner_isspace(*nextp))
		nextp++;				/* skip leading whitespace */

	if (*nextp == '\0')
		return true;			/* allow empty string */

	/* At the top of the loop, we are at start of a new identifier. */
	do
	{
		char	   *curname;
		char	   *endp;

		if (*nextp == '"')
		{
			/* Quoted name --- collapse quote-quote pairs */
			curname = nextp + 1;
			for (;;)
			{
				endp = strchr(nextp + 1, '"');
				if (endp == NULL)
					return false;	/* mismatched quotes */
				if (endp[1] != '"')
					break;		/* found end of quoted name */
				/* Collapse adjacent quotes into one quote, and look again */
				memmove(endp, endp + 1, strlen(endp));
				nextp = endp;
			}
			/* endp now points at the terminating quote */
			nextp = endp + 1;
		}
		else
		{
			/* Unquoted name --- extends to separator or whitespace */
			curname = nextp;
			while (*nextp && *nextp != separator &&
					!scanner_isspace(*nextp))
				nextp++;
			endp = nextp;
			if (curname == nextp)
				return false;	/* empty unquoted name not allowed */
		}

		while (scanner_isspace(*nextp))
			nextp++;			/* skip trailing whitespace */

		if (*nextp == separator)
		{
			nextp++;
			while (scanner_isspace(*nextp))
				nextp++;		/* skip leading whitespace for next */
			/* we expect another name, so done remains false */
		}
		else if (*nextp == '\0')
			done = true;
		else
			return false;		/* invalid syntax */

		/* Now safe to overwrite separator with a null */
		*endp = '\0';

		/*
		 * Finished isolating current name --- add it to list
		 */
		*namelist = lappend(*namelist, curname);

		/* Loop back if we didn't reach end of string */
	}
	while (!done);

	return true;
}
