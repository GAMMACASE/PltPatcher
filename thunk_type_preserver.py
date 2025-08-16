# MIT License
# 
# Copyright (c) 2025 GAMMACASE
# https://github.com/GAMMACASE/PltPatcher

import idaapi
import ida_hexrays

class HexRaysHooks(ida_hexrays.Hexrays_Hooks):
	traversed_ea = set()

	def __init__(self):
		super().__init__()

	def _freeze_tinfo(self, ea):
		if ea in self.traversed_ea:
			return

		func = idaapi.get_func(ea)
		if func and (func.flags & idaapi.FUNC_THUNK):
			tinfo = idaapi.tinfo_t()
			if idaapi.get_tinfo(tinfo, ea):
				# Mark as user-defined to preserve
				self.traversed_ea.add(ea)
				idaapi.apply_tinfo(ea, tinfo, idaapi.TINFO_DEFINITE)
		return

	def _get_called_functions(self, cfunc):
		callees = set()
		
		for x in cfunc.treeitems:
			self._find_calls_in_expr(x, callees)
		return callees

	def _find_calls_in_expr(self, expr, callees):
		if expr is None:
			return
		
		if expr.op == ida_hexrays.cot_call:
			callees.add(expr.cexpr.x.obj_ea)

	def func_printed(self, cfunc):
		if not cfunc:
			return 0

		for callee_ea in self._get_called_functions(cfunc):
			self._freeze_tinfo(callee_ea)
		
		return 0

class ThunkTypePreserver(idaapi.plugin_t):
	flags = 0
	comment = 'Thunk Type Preserver'
	help = 'Preserves thunk guessed type information'
	wanted_name = 'Thunk Type Preserver'

	thunk_hook = None

	def init(self):
		if 'ELF64' not in idaapi.get_file_type_name():
			return idaapi.PLUGIN_SKIP

		if not ida_hexrays.init_hexrays_plugin():
			print('Failed to initialize plugin, missing hexrays decompiler.')
			return idaapi.PLUGIN_SKIP

		self.thunk_hook = HexRaysHooks()
		self.thunk_hook.hook()

		return idaapi.PLUGIN_KEEP

	def run(self, arg):
		pass

	def term(self):
		if self.thunk_hook is not None:
			self.thunk_hook.unhook()


def PLUGIN_ENTRY():
	return ThunkTypePreserver()