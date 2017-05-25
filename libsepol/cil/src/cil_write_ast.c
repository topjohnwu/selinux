#include <stdlib.h>

#include "cil_flavor.h"
#include "cil_internal.h"
#include "cil_log.h"
#include "cil_tree.h"

struct cil_args_write {
	FILE *cil_out;
	struct cil_db *db;
};

static int cil_unfill_expr(struct cil_list *expr_str, char **out_str, int paren);
static int cil_unfill_classperms_list(struct cil_list *classperms, char **out_str, int paren);
static int __cil_write_first_child_helper(struct cil_tree_node *node, void *extra_args);
static int __cil_write_node_helper(struct cil_tree_node *node, uint32_t *finished, void *extra_args);
static int __cil_write_last_child_helper(struct cil_tree_node *node, void *extra_args);

static int __cil_strlist_concat(struct cil_list *str_list, char **out_str, int paren) {
	size_t len = paren ? 3 : 1;
	size_t num_elems = 0;
	char *p = NULL;
	struct cil_list_item *curr;

	/* get buffer size */
	cil_list_for_each(curr, str_list) {
		len += strlen((char *)curr->data);
		num_elems++;
	}
	if (num_elems != 0) {
		/* add spaces between elements */
		len += num_elems - 1;
	}
	*out_str = cil_malloc(len);
	p = *out_str;
	if (paren)
		*p++ = '(';
	cil_list_for_each(curr, str_list) {
		size_t src_len = strlen((char *)curr->data);
		memcpy(p, curr->data, src_len);
		p += src_len;
		if (curr->next != NULL)
			*p++ = ' ';
	}
	if (paren)
		*p++ = ')';
	*p++ = '\0';
	return SEPOL_OK;
}

static int __cil_unfill_expr_helper(struct cil_list_item *curr,
			     struct cil_list_item **next, char **out_str, int paren) {
	int rc = SEPOL_ERR;
	char *str = NULL;
	char *operand1 = NULL;
	char *operand2 = NULL;

	switch(curr->flavor) {
	case CIL_LIST:
		rc = cil_unfill_expr((struct cil_list *)curr->data, &str, paren);
		if (rc != SEPOL_OK)
			goto exit;
		*out_str = str;
		*next = curr->next;
		break;
	case CIL_STRING:
		str = strdup((char *)curr->data);
		if (!str) {
			cil_log(CIL_ERR, "OOM. Unable to copy string.\n");
            rc = SEPOL_ERR;
			goto exit;
		}
		*out_str = str;
		*next = curr->next;
		break;
	case CIL_DATUM:
		str = strdup(((struct cil_symtab_datum *)curr->data)->name);
		if (!str) {
			cil_log(CIL_ERR, "OOM. Unable to copy string.\n");
            rc = SEPOL_ERR;
			goto exit;
		}
		*out_str = str;
		*next = curr->next;
		break;
	case CIL_OP: {
		char *op_str = NULL;
		size_t len = 0;
		enum cil_flavor op_flavor = (enum cil_flavor)curr->data;
		switch (op_flavor) {
		case CIL_AND:
			op_str = CIL_KEY_AND;
			break;
		case CIL_OR:
			op_str = CIL_KEY_OR;
			break;
		case CIL_NOT:
			op_str = CIL_KEY_NOT;
			break;
		case CIL_ALL:
			op_str = CIL_KEY_ALL;
			break;
		case CIL_EQ:
			op_str = CIL_KEY_EQ;
			break;
		case CIL_NEQ:
			op_str = CIL_KEY_NEQ;
			break;
		case CIL_RANGE:
			op_str = CIL_KEY_RANGE;
			break;
		case CIL_XOR:
			op_str = CIL_KEY_XOR;
			break;
		case CIL_CONS_DOM:
			op_str = CIL_KEY_CONS_DOM;
			break;
		case CIL_CONS_DOMBY:
			op_str = CIL_KEY_CONS_DOMBY;
			break;
		case CIL_CONS_INCOMP:
			op_str = CIL_KEY_CONS_INCOMP;
			break;
		default:
			cil_log(CIL_ERR, "Unknown operator in expression: %d\n", op_flavor);
			goto exit;
			break;
		}
		/* all operands take two args except for 'all' and 'not', which take
		 * one and two, respectively */
		len = strlen(op_str) + 3;
		if (op_flavor == CIL_ALL) {
			*out_str = cil_malloc(len);
			sprintf(*out_str, "(%s)", op_str);
			*next = curr->next;
		} else if (op_flavor == CIL_NOT) {
			rc = __cil_unfill_expr_helper(curr->next, next, &operand1, paren);
			if (rc != SEPOL_OK)
				goto exit;
			len += strlen(operand1) + 1;
			*out_str = cil_malloc(len);
			sprintf(*out_str, "(%s %s)", op_str, operand1);
			// *next already set by recursive call
		} else {
			rc = __cil_unfill_expr_helper(curr->next, next, &operand1, paren);
			if (rc != SEPOL_OK)
				goto exit;
			len += strlen(operand1) + 1;
			// *next contains operand2, but keep track of next after that
			rc = __cil_unfill_expr_helper(*next, next, &operand2, paren);
			if (rc != SEPOL_OK)
				goto exit;
			len += strlen(operand2) + 1;
			*out_str = cil_malloc(len);
			sprintf(*out_str, "(%s %s %s)", op_str, operand1, operand2);
			// *next already set by recursive call
		}
	}
		break;
	case CIL_CONS_OPERAND: {
		enum cil_flavor operand_flavor = (enum cil_flavor)curr->data;
		char *operand_str = NULL;
		switch (operand_flavor) {
		case CIL_CONS_U1:
			operand_str = CIL_KEY_CONS_U1;
			break;
		case CIL_CONS_U2:
			operand_str = CIL_KEY_CONS_U2;
			break;
		case CIL_CONS_U3:
			operand_str = CIL_KEY_CONS_U3;
			break;
		case CIL_CONS_T1:
			operand_str = CIL_KEY_CONS_T1;
			break;
		case CIL_CONS_T2:
			operand_str = CIL_KEY_CONS_T2;
			break;
		case CIL_CONS_T3:
			operand_str = CIL_KEY_CONS_T3;
			break;
		case CIL_CONS_R1:
			operand_str = CIL_KEY_CONS_R1;
			break;
		case CIL_CONS_R2:
			operand_str = CIL_KEY_CONS_R2;
			break;
		case CIL_CONS_R3:
			operand_str = CIL_KEY_CONS_R3;
			break;
		case CIL_CONS_L1:
			operand_str = CIL_KEY_CONS_L1;
			break;
		case CIL_CONS_L2:
			operand_str = CIL_KEY_CONS_L2;
			break;
		case CIL_CONS_H1:
			operand_str = CIL_KEY_CONS_H1;
			break;
		case CIL_CONS_H2:
			operand_str = CIL_KEY_CONS_H2;
			break;
		default:
			cil_log(CIL_ERR, "Unknown operand in expression\n");
			goto exit;
			break;
		}
		str = strdup(operand_str);
		if (!str) {
			cil_log(CIL_ERR, "OOM. Unable to copy string.\n");
            rc = SEPOL_ERR;
			goto exit;
		}
		*out_str = str;
		*next = curr->next;
	}
		break;
	default:
		cil_log(CIL_ERR, "Unknown flavor in expression\n");
		goto exit;
		break;
	}
	rc = SEPOL_OK;
exit:
	free(operand1);
	free(operand2);
	return rc;
}

static int cil_unfill_expr(struct cil_list *expr_str, char **out_str, int paren) {
	int rc = SEPOL_ERR;

	/* reuse cil_list to keep track of strings */
	struct cil_list *str_list = NULL;
	struct cil_list_item *curr = NULL;

	cil_list_init(&str_list, CIL_NONE);

	/* iterate through cil_list, grabbing elements as needed */
	curr = expr_str->head;
	while(curr != NULL) {
		char *str = NULL;
		struct cil_list_item *next = NULL;

		rc = __cil_unfill_expr_helper(curr, &next, &str, paren);
        if (rc != SEPOL_OK)
            goto exit;
		cil_list_append(str_list, CIL_STRING, (void *) str);
		str = NULL;
		curr = next;
	}
	rc = __cil_strlist_concat(str_list, out_str, paren);
	if (rc != SEPOL_OK)
		goto exit;
	rc = SEPOL_OK;
exit:
	cil_list_for_each(curr, str_list) {
		free(curr->data);
	}
	cil_list_destroy(&str_list, 0);
	return rc;
}

static int cil_unfill_cats(struct cil_cats *cats, char **out_str) {
	return cil_unfill_expr(cats->str_expr, out_str, 0);
}

static int cil_unfill_level(struct cil_level *lvl, char **out_str) {
	int rc = SEPOL_ERR;
	size_t len = 0;
	char *sens, *cats = NULL;
	sens = lvl->sens_str;
	len = strlen(sens) + 3; // '()\0'
	if (lvl->cats != NULL) {
		rc = cil_unfill_cats(lvl->cats, &cats);
		if (rc != SEPOL_OK)
			goto exit;
		len += strlen(cats) + 1;
	}
	*out_str = cil_malloc(len);
	if (cats == NULL) {
		if (sprintf(*out_str, "(%s)", sens) < 0) {
			cil_log(CIL_ERR, "Error unpacking and writing level\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		if (sprintf(*out_str, "(%s %s)", sens, cats) < 0) {
			cil_log(CIL_ERR, "Error unpacking and writing level\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	}
	rc = SEPOL_OK;
exit:
	free(cats);
	return rc;
}

static int cil_unfill_levelrange(struct cil_levelrange *lvlrnge, char **out_str) {
	int rc = SEPOL_ERR;
	size_t len = 0;
	char *low = NULL, *high = NULL;
	if (lvlrnge->low_str != NULL) {
		low = strdup(lvlrnge->low_str);
		if (low == NULL) {
			cil_log(CIL_ERR, "OOM. Unable to copy level string.\n");
            rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_unfill_level(lvlrnge->low, &low);
		if (rc != SEPOL_OK)
			goto exit;
	}
	if (lvlrnge->high_str != NULL) {
		high = strdup(lvlrnge->high_str);
		if (high == NULL) {
			cil_log(CIL_ERR, "OOM. Unable to copy level string.\n");
            rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_unfill_level(lvlrnge->high, &high);
		if (rc != SEPOL_OK)
			goto exit;
	}
	len = strlen(low) + strlen(high) + 4;
	*out_str = cil_malloc(len);
	if (sprintf(*out_str, "(%s %s)", low, high) < 0) {
		cil_log(CIL_ERR, "Error unpacking and writing levelrange\n");
		rc = SEPOL_ERR;
		goto exit;
	}
	rc = SEPOL_OK;
exit:
	free(low);
	free(high);
	return rc;
}

static int cil_unfill_context(struct cil_context *context, char **out_str) {
	int rc = SEPOL_ERR;
	size_t len = 0;
	char *user_str, *role_str, *type_str;
	char *range_str = NULL;

	user_str = context->user_str;
	role_str = context->role_str;
	type_str = context->type_str;
	if (context->range_str != NULL) {
		range_str = strdup(context->range_str);
		if (range_str == NULL) {
			cil_log(CIL_ERR, "OOM. Unable to copy range string.\n");
            rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_unfill_levelrange(context->range, &range_str);
		if (rc != SEPOL_OK)
			goto exit;
	}
	len = strlen(user_str) + strlen(role_str) + strlen(type_str)
		+ strlen(range_str) + 6;
	*out_str = cil_malloc(len);
	if (sprintf(*out_str, "(%s %s %s %s)", user_str, role_str, type_str, range_str) < 0) {
		cil_log(CIL_ERR, "Error unpacking and writing context\n");
		rc = SEPOL_ERR;
		goto exit;
	}
	rc = SEPOL_OK;
exit:
	free(range_str);
	return rc;
}

static int cil_unfill_permx(struct cil_permissionx *permx, char **out_str) {
	size_t len = 3;
	int rc = SEPOL_ERR;
	char *kind, *obj;
	char *expr = NULL;

	switch (permx->kind) {
	case CIL_PERMX_KIND_IOCTL:
		kind = CIL_KEY_IOCTL;
		break;
	default:
		cil_log(CIL_ERR, "Unknown permissionx kind: %d\n", permx->kind);
		rc = SEPOL_ERR;
		goto exit;
		break;
	}
	obj = permx->obj_str;
	rc = cil_unfill_expr(permx->expr_str, &expr, 1);
	if (rc != SEPOL_OK)
		goto exit;
	len += strlen(kind) + strlen(obj) + strlen(expr) + 2;
	*out_str = cil_malloc(len);
	if (sprintf(*out_str, "(%s %s %s)", kind, obj, expr) < 0) {
		cil_log(CIL_ERR, "Error writing xperm\n");
		rc = SEPOL_ERR;
		goto exit;
	}
	rc = SEPOL_OK;
exit:
	free(expr);
	return rc;
}

#define cil_write_unsupported(flavor) _cil_write_unsupported(flavor, __LINE__)
static int _cil_write_unsupported(const char *flavor, int line) {
	cil_log(CIL_ERR,
			"flavor \"%s\" is not supported, look in file \"%s\""
			" on line %d to add support.\n", flavor, __FILE__, line);
	return SEPOL_ENOTSUP;
}

static int cil_write_policycap(struct cil_tree_node *node, FILE *cil_out) {
	struct cil_policycap *polcap = (struct cil_policycap *)node->data;
	fprintf(cil_out, "(%s %s)\n", CIL_KEY_POLICYCAP, polcap->datum.name);
	return SEPOL_OK;
}

static int cil_write_perm(struct cil_tree_node *node, FILE *cil_out) {
	struct cil_perm *perm = (struct cil_perm *)node->data;
	fprintf(cil_out, "%s", perm->datum.name);
	if (node->next != NULL)
		fprintf(cil_out, " ");
	return SEPOL_OK;
}


static int cil_write_class(struct cil_tree_node *node, uint32_t *finished,
		     struct cil_args_write *extra_args) {
	int rc = SEPOL_ERR;
	FILE *cil_out = extra_args->cil_out;
	struct cil_symtab_datum *datum = (struct cil_symtab_datum *)node->data;
	char *class_type = (node->flavor == CIL_CLASS) ? CIL_KEY_CLASS : CIL_KEY_COMMON;

	/* print preamble */
	fprintf(cil_out, "(%s %s ", class_type, datum->name);

	if (node->cl_head == NULL) {
		/* no associated perms in this part of tree */
		fprintf(cil_out, "()");
	} else {

		/* visit subtree (perms) */
		rc = cil_tree_walk(node, __cil_write_node_helper,
				   __cil_write_first_child_helper,
				   __cil_write_last_child_helper,
				   extra_args);
		if (rc != SEPOL_OK)
			goto exit;
	}

	/* postamble (trailing paren) */
	fprintf(cil_out, ")\n");
	*finished = CIL_TREE_SKIP_HEAD;
	rc = SEPOL_OK;
exit:
	return rc;
}

static int cil_write_classorder(struct cil_tree_node *node, FILE *cil_out) {
	int rc = SEPOL_ERR;
	char *ord_str = NULL;
	struct cil_classorder *classord = (struct cil_classorder *)node->data;

	/* cil_unfill_expr() has logic to stringify a cil_list, reuse that. */
	rc = cil_unfill_expr(classord->class_list_str, &ord_str, 1);
	if (rc != SEPOL_OK)
		goto exit;
	fprintf(cil_out, "(%s %s)\n", CIL_KEY_CLASSORDER, ord_str);
	rc = SEPOL_OK;
exit:
	free(ord_str);
	return rc;
}

static int cil_write_classcommon(struct cil_tree_node *node, FILE *cil_out) {
	struct cil_classcommon *classcommon = (struct cil_classcommon *)node->data;
	fprintf(cil_out, "(%s %s %s)\n", CIL_KEY_CLASSCOMMON, classcommon->class_str,
		classcommon->common_str);
	return SEPOL_OK;
}

static int cil_write_sid(struct cil_tree_node *node, FILE *cil_out) {
	struct cil_sid *sid = (struct cil_sid *)node->data;
	fprintf(cil_out, "(%s %s)\n", CIL_KEY_SID, sid->datum.name);
	return SEPOL_OK;
}

static int cil_write_sidcontext(struct cil_tree_node *node, FILE *cil_out) {
	int rc = SEPOL_ERR;
	char *sid;
	char *ctx_str = NULL;
	struct cil_sidcontext *sidcon = (struct cil_sidcontext *)node->data;

	sid = sidcon->sid_str;
	if (sidcon->context_str != NULL) {
		ctx_str = strdup(sidcon->context_str);
		if (ctx_str == NULL) {
			cil_log(CIL_ERR, "OOM. Unable to copy context string.\n");
            rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_unfill_context(sidcon->context, &ctx_str);
		if (rc != SEPOL_OK)
			goto exit;
	}
	fprintf(cil_out, "(%s %s %s)\n", CIL_KEY_SIDCONTEXT, sid, ctx_str);
	rc = SEPOL_OK;
exit:
	free(ctx_str);
	return rc;
}

static int cil_write_sidorder(struct cil_tree_node *node, FILE *cil_out) {
	int rc = SEPOL_ERR;
	char *ord_str = NULL;
	struct cil_sidorder *sidord = (struct cil_sidorder *)node->data;

	/* cil_unfill_expr() has logic to stringify a cil_list, reuse that. */
	rc = cil_unfill_expr(sidord->sid_list_str, &ord_str, 1);
	if (rc != SEPOL_OK)
		goto exit;
	fprintf(cil_out, "(%s %s)\n", CIL_KEY_SIDORDER, ord_str);
	rc = SEPOL_OK;
exit:
	free(ord_str);
	return rc;
}

static int cil_write_user(struct cil_tree_node *node, FILE *cil_out) {
	struct cil_user *user = (struct cil_user *)node->data;
	fprintf(cil_out, "(%s %s)\n", CIL_KEY_USER, user->datum.name);
	return SEPOL_OK;
}

static int cil_write_userrole(struct cil_tree_node *node, FILE *cil_out) {
	struct cil_userrole *userrole = (struct cil_userrole *)node->data;
	fprintf(cil_out, "(%s %s %s)\n", CIL_KEY_USERROLE, userrole->user_str,
		userrole->role_str);
	return SEPOL_OK;
}

static int cil_write_userlevel(struct cil_tree_node *node, FILE *cil_out) {
	struct cil_userlevel *usrlvl = (struct cil_userlevel *)node->data;
	int rc = SEPOL_ERR;
	char *usr;
	char *lvl = NULL;

	usr = usrlvl->user_str;
	if (usrlvl->level_str != NULL) {
		lvl = strdup(usrlvl->level_str);
		if (lvl == NULL) {
			cil_log(CIL_ERR, "OOM. Unable to copy level string.\n");
            rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_unfill_level(usrlvl->level, &lvl);
		if (rc != SEPOL_OK)
			goto exit;
	}
	fprintf(cil_out, "(%s %s %s)\n", CIL_KEY_USERLEVEL, usr, lvl);
	rc = SEPOL_OK;
exit:
	free(lvl);
	return rc;
}

static int cil_write_userrange(struct cil_tree_node *node, FILE *cil_out) {
	struct cil_userrange *usrrng = (struct cil_userrange *)node->data;
	int rc = SEPOL_ERR;
	char *usr;
	char *range = NULL;

	usr = usrrng->user_str;
	if (usrrng->range_str != NULL) {
		range = strdup(usrrng->range_str);
		if (range == NULL) {
			cil_log(CIL_ERR, "OOM. Unable to copy levelrange string.\n");
            rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_unfill_levelrange(usrrng->range, &range);
		if (rc != SEPOL_OK)
			goto exit;
	}
	fprintf(cil_out, "(%s %s %s)\n", CIL_KEY_USERRANGE, usr, range);
	rc = SEPOL_OK;
exit:
	free(range);
	return rc;
}

static int cil_write_role(struct cil_tree_node *node, FILE *cil_out) {
	struct cil_role *role = (struct cil_role *)node->data;
	fprintf(cil_out, "(%s %s)\n", CIL_KEY_ROLE, role->datum.name);
	return SEPOL_OK;
}

static int cil_write_roletype(struct cil_tree_node *node, FILE *cil_out) {
	struct cil_roletype *roletype = (struct cil_roletype *)node->data;
	fprintf(cil_out, "(%s %s %s)\n", CIL_KEY_ROLETYPE, roletype->role_str, roletype->type_str);
	return SEPOL_OK;
}

static int cil_write_roleattribute(struct cil_tree_node *node, FILE *cil_out) {
	struct cil_roleattribute *roleattr = (struct cil_roleattribute *)node->data;
	fprintf(cil_out, "(%s %s)\n", CIL_KEY_ROLEATTRIBUTE, roleattr->datum.name);
	return SEPOL_OK;
}

static int cil_write_type(struct cil_tree_node *node, FILE *cil_out) {
	struct cil_type *type = (struct cil_type *)node->data;
	fprintf(cil_out, "(%s %s)\n", CIL_KEY_TYPE, type->datum.name);
	return SEPOL_OK;
}

static int cil_write_typepermissive(struct cil_tree_node *node, FILE *cil_out) {
	struct cil_typepermissive *type = (struct cil_typepermissive *)node->data;
	fprintf(cil_out, "(%s %s)\n", CIL_KEY_TYPEPERMISSIVE, type->type_str);
	return SEPOL_OK;
}

static int cil_write_typeattribute(struct cil_tree_node *node, FILE *cil_out) {
	struct cil_typeattribute *typeattr = (struct cil_typeattribute *)node->data;
	fprintf(cil_out, "(%s %s)\n", CIL_KEY_TYPEATTRIBUTE, typeattr->datum.name);
	return SEPOL_OK;
}

static int cil_write_typeattributeset(struct cil_tree_node *node, FILE *cil_out) {
	int rc = SEPOL_ERR;
	char *typeattr;
	char *set_str = NULL;
	struct cil_typeattributeset *typeattrset = (struct cil_typeattributeset *)node->data;

	typeattr = typeattrset->attr_str;
	rc = cil_unfill_expr(typeattrset->str_expr, &set_str, 1);
	if (rc != SEPOL_OK)
		goto exit;

	fprintf(cil_out, "(%s %s %s)\n", CIL_KEY_TYPEATTRIBUTESET, typeattr, set_str);
	rc = SEPOL_OK;
exit:
	free(set_str);
	return rc;
}

static int cil_write_expandtypeattribute(struct cil_tree_node *node, FILE *cil_out)
{
	int rc = SEPOL_ERR;
	char *attr_strs = NULL;
	struct cil_expandtypeattribute *expandattr = (struct cil_expandtypeattribute *)node->data;

	rc = cil_unfill_expr(expandattr->attr_strs, &attr_strs, 1);
	if (rc != SEPOL_OK)
		goto exit;

	fprintf(cil_out, "(%s %s %s)\n", CIL_KEY_EXPANDTYPEATTRIBUTE, attr_strs,
		expandattr->expand ? CIL_KEY_CONDTRUE : CIL_KEY_CONDFALSE);
	rc = SEPOL_OK;
exit:
	free(attr_strs);
	return rc;
}

static int cil_write_alias(struct cil_tree_node *node, FILE *cil_out) {
	int rc = SEPOL_ERR;
	char *type;
	struct cil_alias *alias = (struct cil_alias *)node->data;

	switch (node->flavor) {
	case CIL_TYPEALIAS:
		type = CIL_KEY_TYPEALIAS;
		break;
	case CIL_SENSALIAS:
		type = CIL_KEY_SENSALIAS;
		break;
	case CIL_CATALIAS:
		type = CIL_KEY_CATALIAS;
		break;
	default:
		cil_log(CIL_ERR, "Unknown alias type: %d\n", node->flavor);
		rc = SEPOL_ERR;
		goto exit;
		break;
	}
	fprintf(cil_out, "(%s %s)\n", type, alias->datum.name);
	rc = SEPOL_OK;
exit:
	return rc;
}

static int cil_write_aliasactual(struct cil_tree_node *node, FILE *cil_out) {
	int rc = SEPOL_ERR;
	char *type, *alias, *actual;
	struct cil_aliasactual *aliasact = (struct cil_aliasactual *)node->data;

	switch (node->flavor) {
	case CIL_TYPEALIASACTUAL:
		type = CIL_KEY_TYPEALIASACTUAL;
		break;
	case CIL_SENSALIASACTUAL:
		type = CIL_KEY_SENSALIASACTUAL;
		break;
	case CIL_CATALIASACTUAL:
		type = CIL_KEY_CATALIASACTUAL;
		break;
	default:
		cil_log(CIL_ERR, "Unknown alias type: %d\n", node->flavor);
		rc = SEPOL_ERR;
		goto exit;
		break;
	}
	alias = aliasact->alias_str;
	actual = aliasact->actual_str;
	fprintf(cil_out, "(%s %s %s)\n", type, alias, actual);
	rc = SEPOL_OK;
exit:
	return rc;
}

static int cil_write_nametypetransition(struct cil_tree_node *node, FILE *cil_out) {
	char *src, *tgt, *obj, *res, *name;
	struct cil_nametypetransition *ntrans = (struct cil_nametypetransition *)node->data;

	src = ntrans->src_str;
	tgt = ntrans->tgt_str;
	obj = ntrans->obj_str;
	res = ntrans->result_str;
	name = ntrans->name_str;
	fprintf(cil_out, "(%s %s %s %s \"%s\" %s)\n", CIL_KEY_TYPETRANSITION,
		src, tgt, obj, name, res);
	return SEPOL_OK;
}

static int cil_write_avrule_x(struct cil_avrule *avrule, FILE *cil_out) {
	int rc = SEPOL_ERR;
	char *rulekind, *src, *tgt;
	char *xperms = NULL;

	switch (avrule->rule_kind) {
	case CIL_AVRULE_ALLOWED:
		rulekind = CIL_KEY_ALLOWX;
		break;
	case CIL_AVRULE_AUDITALLOW:
		rulekind = CIL_KEY_AUDITALLOWX;
		break;
	case CIL_AVRULE_DONTAUDIT:
		rulekind = CIL_KEY_DONTAUDITX;
		break;
	case CIL_AVRULE_NEVERALLOW:
		rulekind = CIL_KEY_NEVERALLOWX;
		break;
	default:
		cil_log(CIL_ERR, "Unknown AVRULE type: %d\n", avrule->rule_kind);
		rc = SEPOL_ERR;
		goto exit;
		break;
	}
	src = avrule->src_str;
	tgt = avrule->tgt_str;

	if (avrule->perms.x.permx_str != NULL) {
		xperms = strdup(avrule->perms.x.permx_str);
		if (xperms == NULL) {
			cil_log(CIL_ERR, "OOM. Unable to copy xperms string.\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_unfill_permx(avrule->perms.x.permx, &xperms);
		if (rc != SEPOL_OK)
			goto exit;
	}
	fprintf(cil_out, "(%s %s %s %s)\n", rulekind, src, tgt, xperms);
	rc = SEPOL_OK;
exit:
	free(xperms);
	return rc;
}

static int cil_write_avrule_orig(struct cil_avrule *avrule, FILE *cil_out) {
	int rc = SEPOL_ERR;
	char *rulekind, *src, *tgt;
	char *classperms = NULL;

	switch (avrule->rule_kind) {
	case CIL_AVRULE_ALLOWED:
		rulekind = CIL_KEY_ALLOW;
		break;
	case CIL_AVRULE_AUDITALLOW:
		rulekind = CIL_KEY_AUDITALLOW;
		break;
	case CIL_AVRULE_DONTAUDIT:
		rulekind = CIL_KEY_DONTAUDIT;
		break;
	case CIL_AVRULE_NEVERALLOW:
		rulekind = CIL_KEY_NEVERALLOW;
		break;
	default:
		cil_log(CIL_ERR, "Unknown AVRULE type: %d\n", avrule->rule_kind);
		rc = SEPOL_ERR;
		goto exit;
		break;
	}
	src = avrule->src_str;
	tgt = avrule->tgt_str;

	rc = cil_unfill_classperms_list(avrule->perms.classperms, &classperms, 0);
	if (rc != SEPOL_OK)
		goto exit;
	fprintf(cil_out, "(%s %s %s %s)\n", rulekind, src, tgt, classperms);
	rc = SEPOL_OK;
exit:
	free(classperms);
	return rc;
}

static int cil_write_avrule(struct cil_tree_node *node, FILE *cil_out) {
	int rc = SEPOL_ERR;
	struct cil_avrule *avrule = (struct cil_avrule *)node->data;

	if (avrule->is_extended)
		rc = cil_write_avrule_x(avrule, cil_out);
	else
		rc = cil_write_avrule_orig(avrule, cil_out);
	return rc;
}

static int cil_write_type_rule(struct cil_tree_node *node, FILE *cil_out) {
	int rc = SEPOL_ERR;
	char *type, *src, *tgt, *obj, *res;
	struct cil_type_rule *typerule = (struct cil_type_rule *)node->data;

	switch (typerule->rule_kind) {
	case CIL_TYPE_TRANSITION:
		type = CIL_KEY_TYPETRANSITION;
		break;
	case CIL_TYPE_MEMBER:
		type = CIL_KEY_TYPEMEMBER;
		break;
	case CIL_TYPE_CHANGE:
		type = CIL_KEY_TYPECHANGE;
		break;
	default:
		cil_log(CIL_ERR, "Unknown TYPERULE type: %d\n", typerule->rule_kind);
		rc = SEPOL_ERR;
		goto exit;
		break;
	}
	src = typerule->src_str;
	tgt = typerule->tgt_str;
	obj = typerule->obj_str;
	res = typerule->result_str;
	fprintf(cil_out, "(%s %s %s %s %s)\n", type, src, tgt, obj, res);
	rc = SEPOL_OK;
exit:
	return rc;
}

static int cil_write_sens(struct cil_tree_node *node, FILE *cil_out) {
	struct cil_sens *sens = (struct cil_sens *)node->data;
	fprintf(cil_out, "(%s %s)\n", CIL_KEY_SENSITIVITY, sens->datum.name);
	return SEPOL_OK;
}

static int cil_write_cat(struct cil_tree_node *node, FILE *cil_out) {
	struct cil_cat *cat = (struct cil_cat *)node->data;
	fprintf(cil_out, "(%s %s)\n", CIL_KEY_CATEGORY, cat->datum.name);
	return SEPOL_OK;
}

static int cil_write_senscat(struct cil_tree_node *node, FILE *cil_out) {
	int rc = SEPOL_ERR;
	char *sens;
	char *cats = NULL;
	struct cil_senscat *senscat = (struct cil_senscat *)node->data;

	sens = senscat->sens_str;
	rc = cil_unfill_cats(senscat->cats, &cats);
	if (rc != SEPOL_OK)
		goto exit;
	/* TODO: deal with extra/missing parens */
	fprintf(cil_out, "(%s %s (%s))\n", CIL_KEY_SENSCAT, sens, cats);
	rc = SEPOL_OK;
exit:
	free(cats);
	return rc;
}

static int cil_write_catorder(struct cil_tree_node *node, FILE *cil_out) {
	int rc = SEPOL_ERR;
	char *ord_str = NULL;
	struct cil_catorder *catord = (struct cil_catorder *)node->data;

	/* cil_unfill_expr() has logic to stringify a cil_list, reuse that. */
	rc = cil_unfill_expr(catord->cat_list_str, &ord_str, 1);
	if (rc != SEPOL_OK)
		goto exit;
	fprintf(cil_out, "(%s %s)\n", CIL_KEY_CATORDER, ord_str);
	rc = SEPOL_OK;
exit:
	free(ord_str);
	return rc;
}

static int cil_write_sensorder(struct cil_tree_node *node, FILE *cil_out) {
	int rc = SEPOL_ERR;
	char *ord_str = NULL;
	struct cil_sensorder *sensord = (struct cil_sensorder *)node->data;

	/* cil_unfill_expr() has logic to stringify a cil_list, reuse that. */
	rc = cil_unfill_expr(sensord->sens_list_str, &ord_str, 1);
	if (rc != SEPOL_OK)
		goto exit;
	fprintf(cil_out, "(%s %s)\n", CIL_KEY_SENSITIVITYORDER, ord_str);
	rc = SEPOL_OK;
exit:
	free(ord_str);
	return rc;
}

static int cil_write_genfscon(struct cil_tree_node *node, FILE *cil_out) {
	int rc = SEPOL_ERR;
	char *ctx_str = NULL;

	struct cil_genfscon *genfscon = (struct cil_genfscon *)node->data;
	if (genfscon->context_str != NULL) {
		ctx_str = strdup(genfscon->context_str);
		if (ctx_str == NULL) {
			cil_log(CIL_ERR, "OOM. Unable to copy context string.\n");
            rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_unfill_context(genfscon->context, &ctx_str);
		if (rc != SEPOL_OK)
			goto exit;
	}
	fprintf(cil_out, "(%s %s %s %s)\n", CIL_KEY_GENFSCON, genfscon->fs_str,
            genfscon->path_str, ctx_str);
	rc = SEPOL_OK;
exit:
	free(ctx_str);
	return rc;
}

static int cil_unfill_classperms(struct cil_list_item *curr, char **out_str) {
	int rc = SEPOL_ERR;
	size_t len = 3;
	char *class_str;
	char *perms_str = NULL;
	struct cil_classperms *cp = (struct cil_classperms *)curr->data;

	class_str = cp->class_str;
	len += strlen(class_str) + 1;

	/* fill_perms just calls gen_expr */
	rc = cil_unfill_expr(cp->perm_strs, &perms_str, 1);
	if (rc != SEPOL_OK)
		goto exit;
	len += strlen(perms_str);
	*out_str = cil_malloc(len);
	sprintf(*out_str, "(%s %s)", class_str, perms_str);
	rc = SEPOL_OK;
exit:
	free(perms_str);
	return rc;
}

static int cil_unfill_classperms_list(struct cil_list *classperms, char **out_str, int paren) {
	int rc = SEPOL_ERR;
	struct cil_list_item *curr;
	char *str = NULL;

	/* reuse cil_list to keep track of strings */
	struct cil_list *str_list = NULL;
	cil_list_init(&str_list, CIL_NONE);
	cil_list_for_each(curr, classperms) {
		switch (curr->flavor) {
		case CIL_CLASSPERMS_SET:
			str = strdup(((struct cil_classperms_set *)curr->data)->set_str);
			if (str == NULL) {
				cil_log(CIL_ERR, "OOM. Unable to copy classpermset.\n");
                rc = SEPOL_ERR;
				goto exit;
			}
			break;
		case CIL_CLASSPERMS:
			rc = cil_unfill_classperms(curr, &str);
			if (rc != SEPOL_OK)
				goto exit;
			break;
		default:
			cil_log(CIL_ERR, "Unrecognized classperms flavor\n.");
			goto exit;
		}
		cil_list_append(str_list, CIL_STRING, (void *) str);
		str = NULL;
	}
	rc = __cil_strlist_concat(str_list, out_str, paren);
	if (rc != SEPOL_OK)
		goto exit;
	rc = SEPOL_OK;
exit:
	cil_list_for_each(curr, str_list) {
		free(curr->data);
	}
	cil_list_destroy(&str_list, 0);
	return rc;
}

static int cil_write_fsuse(struct cil_tree_node *node, FILE *cil_out) {
	int rc = SEPOL_ERR;
	struct cil_fsuse *fsuse = (struct cil_fsuse *)node->data;
	char *type, *fsname;
	char *ctx_str = NULL;

	switch(fsuse->type) {
	case CIL_FSUSE_XATTR:
		type = CIL_KEY_XATTR;
		break;
	case CIL_FSUSE_TASK:
		type = CIL_KEY_TASK;
		break;
	case CIL_FSUSE_TRANS:
		type = CIL_KEY_TRANS;
		break;
	default:
		cil_log(CIL_ERR, "Unrecognized fsuse type\n");
		rc = SEPOL_ERR;
		goto exit;
		break;
	}

	fsname = fsuse->fs_str;
	if (fsuse->context_str != NULL) {
		ctx_str = strdup(fsuse->context_str);
		if (ctx_str == NULL) {
			cil_log(CIL_ERR, "OOM. Unable to copy context string.\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_unfill_context(fsuse->context, &ctx_str);
		if (rc != SEPOL_OK)
			goto exit;
	}
	fprintf(cil_out, "(%s %s %s %s)\n", CIL_KEY_FSUSE, type, fsname, ctx_str);
exit:
	free(ctx_str);
	return rc;
}

static int cil_write_constrain(struct cil_tree_node *node, FILE *cil_out) {
	int rc = SEPOL_ERR;
	struct cil_constrain *cons = (struct cil_constrain *)node->data;
	char *flav;
	char *classperms = NULL;
	char *expr = NULL;

	flav = (node->flavor == CIL_CONSTRAIN) ? CIL_KEY_CONSTRAIN : CIL_KEY_MLSCONSTRAIN;

	rc = cil_unfill_classperms_list(cons->classperms, &classperms, 0);
	if (rc != SEPOL_OK)
		goto exit;

	rc = cil_unfill_expr(cons->str_expr, &expr, 0);
	if (rc != SEPOL_OK)
		goto exit;

	fprintf(cil_out, "(%s %s %s)\n", flav, classperms, expr);
exit:
	free(classperms);
	free(expr);
	return rc;
}

static int cil_write_handleunknown(struct cil_tree_node *node, FILE *cil_out) {
	int rc = SEPOL_OK;
	struct cil_handleunknown *handunknown = (struct cil_handleunknown *)node->data;
	char *val = NULL;
	switch (handunknown->handle_unknown) {
	case SEPOL_ALLOW_UNKNOWN:
		val = CIL_KEY_HANDLEUNKNOWN_ALLOW;
		break;
	case SEPOL_DENY_UNKNOWN:
		val = CIL_KEY_HANDLEUNKNOWN_DENY;
		break;
	case SEPOL_REJECT_UNKNOWN:
		val = CIL_KEY_HANDLEUNKNOWN_REJECT;
		break;
	default:
		cil_log(CIL_ERR, "Unknown handleunknown value: %d.\n",
			handunknown->handle_unknown);
		rc = SEPOL_ERR;
		goto exit;
		break;
	}
	fprintf(cil_out, "(%s %s)\n", CIL_KEY_HANDLEUNKNOWN, val);
exit:
	return rc;
}

static int cil_write_mls(struct cil_tree_node *node, FILE *cil_out) {
	int rc = SEPOL_OK;
	struct cil_mls *mls = (struct cil_mls *)node->data;
	char *val = NULL;
	switch (mls->value) {
	case CIL_TRUE:
		val = CIL_KEY_CONDTRUE;
		break;
	case CIL_FALSE:
		val = CIL_KEY_CONDFALSE;
		break;
	default:
		cil_log(CIL_ERR, "Unknown mls value: %d.\n", mls->value);
		rc = SEPOL_ERR;
		goto exit;
		break;
	}
	fprintf(cil_out, "(%s %s)\n", CIL_KEY_MLS, val);
exit:
	return rc;
}

static int __cil_write_first_child_helper(struct cil_tree_node *node, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_args_write *args = (struct cil_args_write *) extra_args;
	FILE *cil_out = NULL;

	if (node == NULL || extra_args == NULL) {
		goto exit;
	}

	cil_out = args->cil_out;

	if (node->parent && node->parent->flavor != CIL_ROOT && node->parent->flavor != CIL_SRC_INFO)
		fprintf(cil_out,"(");
	rc = SEPOL_OK;
exit:
	return rc;
}

static int __cil_write_node_helper(struct cil_tree_node *node, uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_OK;
	struct cil_db *db = NULL;
	struct cil_args_write *args = NULL;
	FILE *cil_out = NULL;

	if (node == NULL || extra_args == NULL) {
		goto exit;
	}

	args = extra_args;
	db = args->db;
	cil_out = args->cil_out;

	switch (node->flavor) {
	case CIL_BLOCK:
		rc = cil_write_unsupported("CIL_BLOCK");
		break;
	case CIL_BLOCKABSTRACT:
		rc = cil_write_unsupported("CIL_BLOCKABSTRACT");
		break;
	case CIL_BLOCKINHERIT:
		rc = cil_write_unsupported("CIL_BLOCKINHERIT");
		break;
	case CIL_IN:
		rc = cil_write_unsupported("CIL_IN");
		break;
	case CIL_POLICYCAP:
		cil_write_policycap(node, cil_out);
		break;
	case CIL_PERM:
		rc = cil_write_perm(node, cil_out);
		break;
	case CIL_MAP_PERM:
		rc = cil_write_unsupported("CIL_MAP_PERM");
		break;
	case CIL_CLASSMAPPING:
		rc = cil_write_unsupported("CIL_CLASSMAPPING");
		break;
	case CIL_CLASS:
		rc = cil_write_class(node, finished, extra_args);
		break;
	case CIL_COMMON:
		rc = cil_write_class(node, finished, extra_args);
		break;
	case CIL_MAP_CLASS:
		rc = cil_write_unsupported("CIL_MAP_CLASS");
		break;
	case CIL_CLASSORDER:
		rc = cil_write_classorder(node, cil_out);
		break;
	case CIL_CLASSPERMISSION:
		rc = cil_write_unsupported("CIL_CLASSPERMISSION");
		break;
	case CIL_CLASSPERMISSIONSET:
		rc = cil_write_unsupported("CIL_CLASSPERMISSIONSET");
		break;
	case CIL_CLASSCOMMON:
		rc = cil_write_classcommon(node, cil_out);
		break;
	case CIL_SID:
		rc = cil_write_sid(node, cil_out);
		break;
	case CIL_SIDCONTEXT:
		rc = cil_write_sidcontext(node, cil_out);
		break;
	case CIL_SIDORDER:
		rc = cil_write_sidorder(node, cil_out);
		break;
	case CIL_USER:
		rc = cil_write_user(node, cil_out);
		break;
	case CIL_USERATTRIBUTE:
		rc = cil_write_unsupported("CIL_USERATTRIBUTE");
		break;
	case CIL_USERATTRIBUTESET:
		rc = cil_write_unsupported("CIL_USERATTRIBUTESET");
		break;
	case CIL_USERROLE:
		rc = cil_write_userrole(node, cil_out);
		break;
	case CIL_USERLEVEL:
		rc = cil_write_userlevel(node, cil_out);
		break;
	case CIL_USERRANGE:
		rc = cil_write_userrange(node, cil_out);
		break;
	case CIL_USERBOUNDS:
		rc = cil_write_unsupported("CIL_USERBOUNDS");
		break;
	case CIL_USERPREFIX:
		rc = cil_write_unsupported("CIL_USERPREFIX");
		break;
	case CIL_ROLE:
		rc = cil_write_role(node, cil_out);
		break;
	case CIL_ROLETYPE:
		rc = cil_write_roletype(node, cil_out);
		break;
	case CIL_ROLEBOUNDS:
		rc = cil_write_unsupported("CIL_ROLEBOUNDS");
		break;
	case CIL_ROLEATTRIBUTE:
		cil_write_roleattribute(node, cil_out);
		break;
	case CIL_ROLEATTRIBUTESET:
		rc = cil_write_unsupported("CIL_ROLEATTRIBUTESET");
		break;
	case CIL_ROLEALLOW:
		rc = cil_write_unsupported("CIL_ROLEALLOW");
		break;
	case CIL_TYPE:
		rc = cil_write_type(node, cil_out);
		break;
	case CIL_TYPEBOUNDS:
		rc = cil_write_unsupported("CIL_TYPEBOUNDS");
		break;
	case CIL_TYPEPERMISSIVE:
		rc = cil_write_typepermissive(node, cil_out);
		break;
	case CIL_TYPEATTRIBUTE:
		rc = cil_write_typeattribute(node, cil_out);
		break;
	case CIL_TYPEATTRIBUTESET:
		rc = cil_write_typeattributeset(node, cil_out);
		break;
    case CIL_EXPANDTYPEATTRIBUTE:
        rc = cil_write_expandtypeattribute(node, cil_out);
        break;
	case CIL_TYPEALIAS:
		rc = cil_write_alias(node, cil_out);
		break;
	case CIL_TYPEALIASACTUAL:
		rc = cil_write_aliasactual(node, cil_out);
		break;
	case CIL_ROLETRANSITION:
		rc = cil_write_unsupported("CIL_ROLETRANSITION");
		break;
	case CIL_NAMETYPETRANSITION:
		rc = cil_write_nametypetransition(node, cil_out);
		break;
	case CIL_RANGETRANSITION:
		rc = cil_write_unsupported("CIL_RANGETRANSITION");
		break;
	case CIL_TUNABLE:
		rc = cil_write_unsupported("CIL_TUNABLE");
		break;
	case CIL_BOOL:
		rc = cil_write_unsupported("CIL_BOOL");
		break;
	case CIL_AVRULE:
	case CIL_AVRULEX:
		rc = cil_write_avrule(node, cil_out);
		break;
	case CIL_PERMISSIONX:
		rc = cil_write_unsupported("CIL_PERMISSIONX");
		break;
	case CIL_TYPE_RULE:
		cil_write_type_rule(node, cil_out);
		break;
	case CIL_SENS:
		rc = cil_write_sens(node, cil_out);
		break;
	case CIL_SENSALIAS:
		rc = cil_write_alias(node, cil_out);
		break;
	case CIL_SENSALIASACTUAL:
		rc = cil_write_aliasactual(node, cil_out);
		break;
	case CIL_CAT:
		rc = cil_write_cat(node, cil_out);
		break;
	case CIL_CATALIAS:
		rc = cil_write_alias(node, cil_out);
		break;
	case CIL_CATALIASACTUAL:
		rc = cil_write_aliasactual(node, cil_out);
		break;
	case CIL_CATSET:
		rc = cil_write_unsupported("CIL_CATSET");
		break;
	case CIL_SENSCAT:
		rc = cil_write_senscat(node, cil_out);
		break;
	case CIL_CATORDER:
		rc = cil_write_catorder(node, cil_out);
		break;
	case CIL_SENSITIVITYORDER:
		rc = cil_write_sensorder(node, cil_out);
		break;
	case CIL_LEVEL:
		rc = cil_write_unsupported("CIL_LEVEL");
		break;
	case CIL_LEVELRANGE:
		rc = cil_write_unsupported("CIL_LEVELRANGE");
		break;
	case CIL_CONTEXT:
		rc = cil_write_unsupported("CIL_CONTEXT");
		break;
	case CIL_NETIFCON:
		rc = cil_write_unsupported("CIL_NETIFCON");
		break;
	case CIL_GENFSCON:
		 rc = cil_write_genfscon(node, cil_out);
		break;
	case CIL_FILECON:
		rc = cil_write_unsupported("CIL_FILECON");
		break;
	case CIL_NODECON:
		rc = cil_write_unsupported("CIL_NODECON");
		break;
	case CIL_PORTCON:
		rc = cil_write_unsupported("CIL_PORTCON");
		break;
	case CIL_PIRQCON:
		rc = cil_write_unsupported("CIL_PIRQCON");
		break;
	case CIL_IOMEMCON:
		rc = cil_write_unsupported("CIL_IOMEMCON");
		break;
	case CIL_IOPORTCON:
		rc = cil_write_unsupported("CIL_IOPORTCON");
		break;
	case CIL_PCIDEVICECON:
		rc = cil_write_unsupported("CIL_PCIDEVICECON");
		break;
	case CIL_DEVICETREECON:
		rc = cil_write_unsupported("CIL_DEVICETREECON");
		break;
	case CIL_FSUSE:
		rc = cil_write_fsuse(node, cil_out);
		break;
	case CIL_CONSTRAIN:
		rc = cil_write_unsupported("CIL_CONSTRAIN");
		break;
	case CIL_MLSCONSTRAIN:
		rc = cil_write_constrain(node, cil_out);
		break;
	case CIL_VALIDATETRANS:
		rc = cil_write_unsupported("CIL_VALIDATETRANS");
		break;
	case CIL_MLSVALIDATETRANS:
		rc = cil_write_unsupported("CIL_MLSVALIDATETRANS");
		break;
	case CIL_CALL:
		rc = cil_write_unsupported("CIL_CALL");
		break;
	case CIL_MACRO:
		rc = cil_write_unsupported("CIL_MACRO");
		break;
	case CIL_NODE:
		rc = cil_write_unsupported("CIL_NODE");
		break;
	case CIL_OPTIONAL:
		rc = cil_write_unsupported("CIL_OPTIONAL");
		break;
	case CIL_IPADDR:
		rc = cil_write_unsupported("CIL_IPADDR");
		break;
	case CIL_CONDBLOCK:
		rc = cil_write_unsupported("CIL_CONDBLOCK");
		break;
	case CIL_BOOLEANIF:
		rc = cil_write_unsupported("CIL_BOOLEANIF");
		break;
	case CIL_TUNABLEIF:
		rc = cil_write_unsupported("CIL_TUNABLEIF");
		break;
	case CIL_DEFAULTUSER:
		rc = cil_write_unsupported("CIL_DEFAULTUSER");
		break;
	case CIL_DEFAULTROLE:
		rc = cil_write_unsupported("CIL_DEFAULTROLE");
		break;
	case CIL_DEFAULTTYPE:
		rc = cil_write_unsupported("CIL_DEFAULTTYPE");
		break;
	case CIL_DEFAULTRANGE:
		rc = cil_write_unsupported("CIL_DEFAULTRANGE");
		break;
	case CIL_SELINUXUSER:
		rc = cil_write_unsupported("CIL_SELINUXUSER");
		break;
	case CIL_SELINUXUSERDEFAULT:
		rc = cil_write_unsupported("CIL_SELINUXUSERDEFAULT");
		break;
	case CIL_HANDLEUNKNOWN:
		rc = cil_write_handleunknown(node, cil_out);
		break;
	case CIL_MLS:
		rc = cil_write_mls(node, cil_out);
		break;
	case CIL_SRC_INFO:
		break;
	case CIL_NONE:
		// TODO: add proper removal support
		*finished = CIL_TREE_SKIP_HEAD;
		break;
	default:
		cil_log(CIL_ERR, "Unknown AST flavor: %d.\n", node->flavor);
		rc = SEPOL_ERR;
		goto exit;
		break;
	}
exit:
	return rc;
}

static int __cil_write_last_child_helper(struct cil_tree_node *node, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_db *db = NULL;
	struct cil_args_write *args = NULL;
	FILE *cil_out = NULL;

	if (node == NULL || extra_args == NULL) {
		goto exit;
	}

	args = extra_args;
	db = args->db;
	cil_out = args->cil_out;

	if (node->parent && node->parent->flavor != CIL_ROOT && node->parent->flavor != CIL_SRC_INFO) {
		fprintf(cil_out,")");
	}
	rc = SEPOL_OK;
exit:
	return rc;
}

/* main exported function */
int cil_write_ast(struct cil_db *db, const char* path) {
	int rc = SEPOL_ERR;
	struct cil_args_write extra_args;
	FILE *cil_out = NULL;

	cil_out = fopen(path, "we");
	if (cil_out == NULL) {
		cil_log(CIL_ERR, "Failure opening output file for writing AST\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	extra_args.cil_out = cil_out;
	extra_args.db = db;
	rc = cil_tree_walk(db->ast->root, __cil_write_node_helper,
			   __cil_write_first_child_helper,
			   __cil_write_last_child_helper,
			   &extra_args);
	if (rc != SEPOL_OK) {
		cil_log(CIL_INFO, "cil_tree_walk failed, rc: %d\n", rc);
		goto exit;
	}

exit:
	fclose(cil_out);
	cil_out = NULL;
	return rc;
}
