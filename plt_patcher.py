# MIT License
# 
# Copyright (c) 2025 GAMMACASE
# https://github.com/GAMMACASE/PltPatcher

import idc
import idaapi
import idautils
import ida_segment

def get_dynamic_struct():
	if get_dynamic_struct.dyn_data is None:
		phoff = idaapi.get_qword(idaapi.inf_get_min_ea() + 0x20) + idaapi.inf_get_min_ea()
		phnum = idaapi.get_word(idaapi.inf_get_min_ea() + 0x38)
		phentsize = idaapi.get_word(idaapi.inf_get_min_ea() + 0x36)
		for i in range(phnum):
			p_type = idaapi.get_dword(phoff + phentsize * i)
			if p_type == 2: # PY_DYNAMIC
				dyn_addr = idaapi.get_qword(phoff + phentsize * i + 0x10)
				dyn_size = idaapi.get_qword(phoff + phentsize * i + 0x18)
				get_dynamic_struct.dyn_data = (dyn_addr, dyn_size)

	return get_dynamic_struct.dyn_data
get_dynamic_struct.dyn_data = None

def find_dynamic_entry(search_tag):
	dyn, dyn_size = get_dynamic_struct()
	for i in range(0, dyn_size, 16):
		tag = idaapi.get_qword(dyn + i)
		ptr = idaapi.get_qword(dyn + i + 8)

		if tag == 0 and ptr == 0:
			break
		
		if tag == search_tag:
			return ptr
	return None

def read_string(ea):
	return idaapi.get_strlit_contents(ea, -1, idaapi.STRTYPE_C).decode('utf-8')

def find_func_in_extern(name):
	seg = idaapi.get_segm_by_name("extern")

	if not seg:
		return None
	
	ea = seg.start_ea
	while ea < seg.end_ea:
		if idc.get_func_name(ea) == name:
			return ea
		ea = idc.next_head(ea)
	
	return None

def add_extern_entry(name):
	seg = idaapi.get_segm_by_name("extern")
	
	if not seg:
		return None

	target_ea = seg.end_ea
	idaapi.set_segm_end(seg.start_ea, seg.end_ea + 8, ida_segment.SEGMOD_KEEP)

	idaapi.put_qword(target_ea, 0)

	if idaapi.add_func(target_ea):
		idaapi.set_name(target_ea, name, idaapi.SN_FORCE)
		return target_ea
	
	return None

def patch_plt():
	jmprel = find_dynamic_entry(0x17)
	strtab = find_dynamic_entry(0x5)
	symtab = find_dynamic_entry(0x6)
	relsz = find_dynamic_entry(0x2)

	if jmprel is None:
		print("!!! Failed to find 'DT_JMPREL' in '_DYNAMIC'")
		return
	if strtab is None:
		print("!!! Failed to find 'DT_STRTAB' in '_DYNAMIC'")
		return
	if symtab is None:
		print("!!! Failed to find 'DT_SYMTAB' in '_DYNAMIC'")
		return
	if relsz is None:
		rel_seg = idaapi.getseg(jmprel)
		relsz = rel_seg.end_ea - jmprel

	for i in range(0, relsz, 24):
		got_plt_offs = idaapi.get_qword(jmprel + i)
		type = idaapi.get_dword(jmprel + i + 0x8)
		sym_offs = idaapi.get_dword(jmprel + i + 0xC)

		if type == 7:
			sym_name_offs = idaapi.get_dword(symtab + sym_offs * 0x18)
			func_name = read_string(strtab + sym_name_offs)

			# Attempt to lookup function in case it's already exists
			target_ea = idc.get_name_ea_simple(func_name)

			if target_ea == idc.BADADDR:
				# Do additional lookup in extern segment in case previous lookup failed
				target_ea = find_func_in_extern(func_name)

				# If it's still not found, add new extern entry
				if target_ea is None:
					target_ea = add_extern_entry(func_name)

			idc.set_name(got_plt_offs, f'{func_name}_ptr', idaapi.SN_FORCE)

			if target_ea is not None:
				# Patch .got.plt entry to point to extern function
				idaapi.put_qword(got_plt_offs, target_ea)
				idaapi.add_dref(got_plt_offs, target_ea, idaapi.dr_O)

				tinfo = idaapi.tinfo_t()

				# Rename and mark as thunk all references to this plt entry
				for addr in idautils.DataRefsTo(got_plt_offs):
					idaapi.add_cref(addr, target_ea, idaapi.fl_CN)
					ref_func = idaapi.get_func(addr)
					if ref_func:
						idc.set_name(ref_func.start_ea, f'_{func_name}', idaapi.SN_FORCE)
						idc.set_func_flags(ref_func.start_ea, ref_func.flags | idaapi.FUNC_THUNK)

					if idaapi.get_tinfo(tinfo, addr):
						idaapi.set_tinfo(target_ea, tinfo, idaapi.TINFO_DEFINITE)
			else:
				print(f'!!! Failed to find/create {got_plt_offs:x} [{func_name}] function in exports')

class PltPatcher(idaapi.plugin_t):
	flags = idaapi.PLUGIN_UNL
	comment = 'Plt Patcher'
	help = 'Patches plt sections when IDA fails'
	wanted_name = 'Patch Plt Section'

	def init(self):
		if 'ELF64' not in idaapi.get_file_type_name():
			return idaapi.PLUGIN_SKIP

		return idaapi.PLUGIN_KEEP

	def run(self, arg):
		print('Starting patching plt section...')

		patch_plt()

		print('Plt patcher finished.')

	def term(self):
		pass


def PLUGIN_ENTRY():
	return PltPatcher()