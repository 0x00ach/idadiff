import idc
import idautils
import string
try:
    import _hashlib
except:
    import hashlib as _hashlib

def shex(a):
    return hex(a).rstrip("L")
def shexst(a):
    return hex(a).rstrip("L").lstrip("0x") or 0
    
def calc_hash(funcAddr):
    func = idaapi.get_func(funcAddr)
    if type(func) == type(None):
        return ""
    flow = idaapi.FlowChart(f=func)
    cur_hash_rev = ""
    addrIds = []
    cur_id = 1
    for c in range(0,flow.size):
        cur_basic = flow.__getitem__(c)
        cur_hash_rev += shex(cur_basic.startEA)+":"
        addrIds.append((shex(cur_basic.startEA),str(cur_id)))
        cur_id += 1
        addr = cur_basic.startEA
        blockEnd = cur_basic.endEA
        mnem = GetMnem(addr)
        while mnem != "":
            if mnem == "call":
                 cur_hash_rev += "c,"
                 addr = NextHead(addr,blockEnd)
                 mnem = GetMnem(addr)
                 if addr != BADADDR:
                    cur_hash_rev += shex(addr)+";"+shex(addr)+":"
                    addrIds.append((shex(addr),str(cur_id)))
                    cur_id += 1
            else:
                addr = NextHead(addr,blockEnd)
                mnem = GetMnem(addr)
        refs = []
        for suc in cur_basic.succs():
            refs.append(suc.startEA)
        refs.sort()
        refsrev = ""
        for ref in refs:
            refsrev += shex(ref)+","
        if refsrev != "":
            refsrev = refsrev[:-1]
        cur_hash_rev +=  refsrev+";"
    for aid in addrIds:
        cur_hash_rev = string.replace(cur_hash_rev,aid[0],aid[1])
    m2 = _hashlib.new("md5")
    m2.update(cur_hash_rev)
    iHash = m2.hexdigest()[-8:]
    return iHash

def sample_source():
	full_hash = ""
	for addr in idautils.Functions(idc.MinEA(),idc.MaxEA()):
			fname = idc.GetFunctionName(addr)
			full_hash = fname+":"+calc_hash(addr)+":"+hex(addr)[2:]+"|"
	print 'x = "' + full_hash + '"'
   
def sample_dest():
	global x
	src_hashes = {}
	for i in x.split("|"):
		z = i.split(":")
		if src_hashes.has_key(z):
			src_hashes[z] = "baadf00d"
		else:
			src_hashes[i[1]] = i[0]
	dst_hashes = {}
	for addr in idautils.Functions(idc.MinEA(),idc.MaxEA()):
			fname = idc.GetFunctionName(addr)
			if fname.startswith("sub_"):
				z = calc_hash(addr)
				if dst_hashes.has_key(z):
					src_hashes[z] = "baadf00d"
				else:
					src_hashes[z] = addr
	for x in dst_hashes:
		if dst_hashes[x] == "baadf00d":
			continue
		if src_hashes.has_key(x):
			if src_hashes[x] != "baadf00d":
				idc.MakeNameEx(dst_hashes[x],src_hashes[x], SN_NOWARN)
	print full_hash
  
def help():
   print "1. In the source sample (renamed subs), run 'sample_source()'"
   print "2. Copy the x = 'XXXXX...XXXX' string"
   print "3. In the dest sample, paste the string"
   print "4. In the dest sample, load the script and run 'sample_dest()'"
   
help()
