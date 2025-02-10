// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_srv6_api.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <errno.h>


static cmd_status_t srv6_steer_add(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_srv6_steer_add_req *req;
	const struct ec_pnode *n;
	const struct ec_strvec *v;
	const char *str;
	size_t len;
	int ret, i;

	// get NEXT sequence node. it is the parent of the first NEXT node.
	n = ec_pnode_find(p, "NEXT");
	if (n == NULL || (n = ec_pnode_get_parent(n)) == NULL || ec_pnode_len(n) < 1)
		return CMD_ERROR;
	len = sizeof(*req) + sizeof(req->s.nh[0]) * ec_pnode_len(n);
	if ((req = calloc(1, len)) == NULL)
		return CMD_ERROR;
	req->s.n_nh = ec_pnode_len(n);

	// parse NEXT list.
	for (n = ec_pnode_get_first_child(n), i = 0; n != NULL;	n = ec_pnode_next(n), i++) {
		v = ec_pnode_get_strvec(n);
		str = ec_strvec_val(v, 0);
		if (inet_pton(AF_INET6, str, &req->s.nh[i]) != 1) {
			free(req);
			return CMD_ERROR;
		}
	}

	if ((str = arg_str(p, "DEST6")) != NULL) {
		if (ip6_net_parse(str, &req->s.dest6, true) < 0)
			return CMD_ERROR;
		req->s.is_dest6 = true;
	} else if ((str = arg_str(p, "DEST4")) != NULL) {
		if (ip4_net_parse(str, &req->s.dest4, true) < 0)
			return CMD_ERROR;
		req->s.is_dest6 = false;
	}

	if (arg_u16(p, "VRF", &req->s.vrf_id) < 0 && errno != ENOENT) {
		free(req);
		return CMD_ERROR;
	}

	// send command
	ret = gr_api_client_send_recv(c, GR_SRV6_STEER_ADD, len, req, NULL);
	free(req);

	return ret < 0 ? CMD_ERROR: CMD_SUCCESS;
}

static cmd_status_t srv6_steer_del(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_srv6_steer_del_req req = {};
	const char *s;

	if ((s = arg_str(p, "DEST6")) != NULL) {
		if (ip6_net_parse(s, &req.s.dest6, true) < 0)
			return CMD_ERROR;
		req.s.is_dest6 = true;
	} else if ((s = arg_str(p, "DEST4")) != NULL) {
		if (ip4_net_parse(s, &req.s.dest4, true) < 0)
			return CMD_ERROR;
		req.s.is_dest6 = false;
	} else {
		return CMD_ERROR;
	}

	if (arg_u16(p, "VRF", &req.s.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_SRV6_STEER_DEL, sizeof (req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t srv6_steer_show(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_srv6_steer_list_req req = { .vrf_id = UINT16_MAX };
	struct gr_srv6_steer_list_resp *resp;
	struct gr_srv6_steer *sd;
	void *ptr, *resp_ptr = NULL;
	int ret, i, j;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	ret = gr_api_client_send_recv(c, GR_SRV6_STEER_LIST, sizeof (req), &req, &resp_ptr);
	if (ret < 0)
		return CMD_ERROR;

	resp = resp_ptr;

	if (resp->n_steer)
		printf(" vrf_id  ip     next\n");
	ptr = resp->steer;
	for (i = 0; i < resp->n_steer; i++) {
		sd = ptr;
		if (sd->is_dest6)
			printf("% 6d " IP6_F, sd->vrf_id, &sd->dest6.ip);
		for (j = 0; j < sd->n_nh; j++) {
			printf(" " IP6_F, &sd->nh[j]);
		}
		printf("\n");
		ptr += sizeof (*sd) + sd->n_nh * sizeof(sd->nh[0]);
	}

	free(resp_ptr);
	return CMD_SUCCESS;
}



static cmd_status_t srv6_localsid_add(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_srv6_localsid_add_req req = { .l.vrf_id = 0 };
	const struct ec_pnode *n;
	const struct ec_strvec *v;

	n = ec_pnode_find(p, "behavior");
	if (n == NULL || (n = ec_pnode_next(n)) == NULL)
		return CMD_ERROR;
	v = ec_pnode_get_strvec(n);
	snprintf(req.l.behavior, sizeof (req.l.behavior), "%s", ec_strvec_val(v, 0));

	if (arg_ip6(p, "SID", &req.l.lsid) < 0)
		return CMD_ERROR;

	if (arg_u16(p, "VRF", &req.l.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_SRV6_LOCALSID_ADD, sizeof (req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}


static cmd_status_t srv6_localsid_del(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_srv6_localsid_del_req req = { .vrf_id = 0 };

	if (arg_ip6(p, "SID", &req.lsid) < 0)
		return CMD_ERROR;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_SRV6_LOCALSID_DEL, sizeof (req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}


static cmd_status_t srv6_localsid_show(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_srv6_localsid_list_req req = { .vrf_id = UINT16_MAX };
	struct gr_srv6_localsid_list_resp *resp;
	struct gr_srv6_localsid *lsid;
	void *resp_ptr = NULL;
	int ret, i;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	ret = gr_api_client_send_recv(c, GR_SRV6_LOCALSID_LIST, sizeof (req), &req, &resp_ptr);
	if (ret < 0)
		return CMD_ERROR;

	resp = resp_ptr;

	if (resp->n_lsid)
		printf(" vrf_id  lsid     behavior\n");
	for (i = 0; i < resp->n_lsid; i++) {
		lsid = &resp->lsid[i];
		printf("% 6d " IP6_F, lsid->vrf_id, &lsid->lsid);
		printf("     %s\n", lsid->behavior);
	}

	free(resp_ptr);
	return CMD_SUCCESS;
}


static int ctx_init(struct ec_node *root) {
	int ret;

	// steer commands
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ADD, CTX_ARG("sr", "Create srv6 stack elements.")),
		"steer dest DEST4|DEST6 next NEXT+ [vrf VRF]",
		srv6_steer_add,
		"Bind a route to a steering policy.",
		with_help("Ipv4 destination prefix to steer", ec_node_re("DEST4", IPV4_NET_RE)),
		with_help("Ipv6 destination prefix to steer", ec_node_re("DEST6", IPV6_NET_RE)),
		with_help("Next SID to visit.", ec_node_re("NEXT", IPV6_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_DEL, CTX_ARG("sr", "Delete srv6 stack elements.")),
		"steer dest DEST4|DEST6 [vrf VRF]",
		srv6_steer_del,
		"Remove a steering policy.",
		with_help("Ipv4 destination prefix to steer", ec_node_re("DEST4", IPV4_NET_RE)),
		with_help("Ipv6 destination prefix to steer", ec_node_re("DEST6", IPV6_NET_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("sr", "Show srv6 stack elements.")),
		"steer [vrf VRF]",
		srv6_steer_show,
		"View all srv6 steering rules",
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;

	// localsid commands
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ADD, CTX_ARG("sr", "Create srv6 stack elements.")),
		"localsid SID behavior (end|end.dt4|end.dt6) [vrf VRF]",
		srv6_localsid_add,
		"Create a new local endpoint.",
		with_help("Local SID.", ec_node_re("SID", IPV6_RE)),
		with_help("SR Endpoint behaviors", ec_node_str("behavior", "behavior")),
		with_help("Behavior 'end'.", ec_node_str("end", "end")),
		with_help("Behavior 'end.dt4'.", ec_node_str("end.dt4", "end.dt4")),
		with_help("Behavior 'end.dt6'.", ec_node_str("end.dt6", "end.dt6")),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_DEL, CTX_ARG("sr", "Delete srv6 stack elements.")),
		"localsid SID [vrf VRF]",
		srv6_localsid_del,
		"Delete a srv6 endpoint.",
		with_help("Local SID.", ec_node_re("SID", IPV6_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("sr", "Show srv6 stack elements.")),
		"localsid [vrf VRF]",
		srv6_localsid_show,
		"View all localsid",
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "srv6",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
