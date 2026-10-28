#include "jbserver.h"
#include "util.h"

#include <libroothider/libroothider.h>

// 校验回复上下文和参数布局，再调用对应处理器。
int jbserver_received_xpc_message(struct jbserver_impl *server, xpc_object_t xmsg)
{
	if (xpc_get_type(xmsg) != XPC_TYPE_DICTIONARY) return -1;

/**********************************************/
	if(roothide_handle_xpc_msg(xmsg)) return -2;
/*********************************************/

	if (!xpc_dictionary_get_value(xmsg, "jb-domain")) return -1;
	if (!xpc_dictionary_get_value(xmsg, "action")) return -1;

	uint64_t domainIdx = xpc_dictionary_get_uint64(xmsg, "jb-domain");
	if (domainIdx == 0) return -1;
	struct jbserver_domain *domain = server->domains[0];
	for (uint64_t i = 1; i < domainIdx && domain; i++) {
		domain = server->domains[i];
	}
	if (!domain) return -1;

	audit_token_t clientToken = { 0 };
	xpc_dictionary_get_audit_token(xmsg, &clientToken);

	if (domain->permissionHandler) {
		if (!domain->permissionHandler(clientToken)) return -2;
	}

	uint64_t actionIdx = xpc_dictionary_get_uint64(xmsg, "action");
	if (actionIdx == 0) return -1;
	struct jbserver_action *action = &domain->actions[0];
	for (uint64_t i = 1; i < actionIdx && action->handler; i++) {
		action = &domain->actions[i];
	}
	if (!action->handler) return -1;

	size_t argCount = 0, slotCount = 0;
	size_t slots[JBSERVER_MAX_ARGS] = { 0 };
	for (; argCount < JBSERVER_MAX_ARGS && action->args[argCount].name; argCount++) {
		const jbserver_arg *desc = &action->args[argCount];
		if (desc->type < JBS_TYPE_BOOL || desc->type > JBS_TYPE_XPC_GENERIC || (desc->out && desc->type == JBS_TYPE_CALLER_TOKEN)) return -1;
		size_t width = desc->type == JBS_TYPE_DATA ? 2 : 1;
		if (width > JBSERVER_MAX_ARGS - slotCount) return -1;
		slots[argCount] = slotCount;
		slotCount += width;
	}

	// 无回复端口时不得执行有副作用的处理器。
	xpc_object_t xreply = xpc_dictionary_create_reply(xmsg);
	if (!xreply) return -1;

	int (*handler)(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8) = action->handler;
	void *args[JBSERVER_MAX_ARGS] = { 0 };
	void *argsOut[JBSERVER_MAX_ARGS] = { 0 };

	for (size_t descIdx = 0; descIdx < argCount; descIdx++) {
		size_t i = slots[descIdx];
		const jbserver_arg *argDesc = &action->args[descIdx];
		if (!argDesc->out) {
			switch (argDesc->type) {
				case JBS_TYPE_BOOL:
				args[i] = (void *)xpc_dictionary_get_bool(xmsg, argDesc->name);
				break;
				case JBS_TYPE_UINT64:
				args[i] = (void *)xpc_dictionary_get_uint64(xmsg, argDesc->name);
				break;
				case JBS_TYPE_FD:
				args[i] = (void *)(int64_t)xpc_dictionary_dup_fd(xmsg, argDesc->name);
				break;
				case JBS_TYPE_MACH_RECV:
				args[i] = (void *)(int64_t)xpc_dictionary_extract_mach_recv(xmsg, argDesc->name);
				break;
				case JBS_TYPE_MACH_SEND:
				args[i] = (void *)(int64_t)xpc_dictionary_copy_mach_send(xmsg, argDesc->name);
				break;
				case JBS_TYPE_STRING:
				args[i] = (void *)xpc_dictionary_get_string(xmsg, argDesc->name);
				break;
				case JBS_TYPE_DATA: {
					size_t length = 0;
					args[i] = (void *)xpc_dictionary_get_data(xmsg, argDesc->name, &length);
					args[i+1] = (void *)length;
					break;
				}
				case JBS_TYPE_ARRAY:
				args[i] = (void *)xpc_dictionary_get_array(xmsg, argDesc->name);
				break;
				case JBS_TYPE_DICTIONARY:
				args[i] = (void *)xpc_dictionary_get_dictionary(xmsg, argDesc->name);
				break;
				case JBS_TYPE_XPC_GENERIC:
				args[i] = (void *)xpc_dictionary_get_value(xmsg, argDesc->name);
				break;
				case JBS_TYPE_CALLER_TOKEN:
				args[i] = (void *)&clientToken;
				break;
			}
		}
		else {
			if (argDesc->type == JBS_TYPE_FD) argsOut[i] = (void *)(intptr_t)-1;
			args[i] = &argsOut[i];
			if (argDesc->type == JBS_TYPE_DATA) args[i+1] = &argsOut[i+1];
		}
	}

	int result = handler(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);

	for (size_t descIdx = 0; descIdx < argCount; descIdx++) {
		size_t i = slots[descIdx];
		const jbserver_arg *argDesc = &action->args[descIdx];
		if (argDesc->out) {
			switch (argDesc->type) {
				case JBS_TYPE_BOOL:
				xpc_dictionary_set_bool(xreply, argDesc->name, (bool)argsOut[i]);
				break;
				case JBS_TYPE_UINT64:
				xpc_dictionary_set_uint64(xreply, argDesc->name, (uint64_t)argsOut[i]);
				break;
				case JBS_TYPE_FD: {
					int fd = (int)(intptr_t)argsOut[i];
					if (fd >= 0) {
						xpc_dictionary_set_fd(xreply, argDesc->name, fd);
						close(fd);
					}
					break;
				}
				case JBS_TYPE_MACH_RECV: {
					xpc_dictionary_set_mach_recv(xreply, argDesc->name, (mach_port_t)(uint64_t)argsOut[i]);
					break;
				}
				case JBS_TYPE_MACH_SEND: {
					xpc_dictionary_set_mach_send(xreply, argDesc->name, (mach_port_t)(uint64_t)argsOut[i]);
					break;
				}
				case JBS_TYPE_STRING: {
					if (argsOut[i]) {
						xpc_dictionary_set_string(xreply, argDesc->name, (char *)argsOut[i]);
						free(argsOut[i]);
					}
					break;
				}
				case JBS_TYPE_DATA: {
					if (argsOut[i]) {
						xpc_dictionary_set_data(xreply, argDesc->name, argsOut[i], (size_t)argsOut[i+1]);
						free(argsOut[i]);
					}
					break;
				}
				case JBS_TYPE_ARRAY:
				case JBS_TYPE_DICTIONARY:
				case JBS_TYPE_XPC_GENERIC: {
					if (argsOut[i]) {
						xpc_dictionary_set_value(xreply, argDesc->name, (xpc_object_t)argsOut[i]);
						xpc_release((xpc_object_t)argsOut[i]);
					}
					break;
				}
				default:
				break;
			}
		}
		else {
			if (argDesc->type == JBS_TYPE_FD) {
				close((int)(int64_t)args[i]);
			}
		}
	}
	xpc_dictionary_set_int64(xreply, "result", result);
	xpc_pipe_routine_reply(xreply);
	xpc_release(xreply);

	return 0;
}
