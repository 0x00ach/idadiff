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
	
def normalize_fname(fname):
	newname = ''
	allowed = 'azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN0123456789_-'
	for c in fname:
		if c in allowed:
			newname += c
		else:
			newname += '_'
	return newname
	
def sample_source():
	global full_hash
	full_hash = ""
	c = 0
	for addr in idautils.Functions(idc.MinEA(),idc.MaxEA()):
		fname = idc.GetFunctionName(addr)
		full_hash += normalize_fname(fname)+":"+calc_hash(addr)+":"+shexst(addr)+"|"
		c = c+1
	if c > 1000:
		print "Too many subs. Plz run:"
		print "SRC SAMPLE : open('lame_ipc.txt','wb').write(full_hash)"
		print "DST SAMPLE : src_data = open('lame_ipc.txt','rb').read(full_hash)"
	else:
		print 'src_data = "' + full_hash + '"'
	return
	
def sample_dest():
	global src_data
	if src_data is None:
		print "run the src_data = ... first"
		return
	src_hashes = {}
	for i in src_data.split("|"):
		z = i.split(":")
		if len(z) < 2:
			continue
		if src_hashes.has_key(z[1]):
			src_hashes[z[1]] = "baadf00d"
		else:
			src_hashes[z[1]] = z[0]
	dst_hashes = {}
	for addr in idautils.Functions(idc.MinEA(),idc.MaxEA()):
			fname = idc.GetFunctionName(addr)
			z = calc_hash(addr)
			if dst_hashes.has_key(z):
				dst_hashes[z] = "baadf00d"
			else:
				dst_hashes[z] = addr
	c = 0
	for tmp in dst_hashes:
		if dst_hashes[tmp] == "baadf00d":
			continue
		if src_hashes.has_key(tmp):
			if src_hashes[tmp] != "baadf00d":
				idc.MakeNameEx(dst_hashes[tmp],"SHARED_"+src_hashes[tmp], SN_NOWARN)
				c = c+1
	print "%d subs have been renamed" % (c)
	return
def help():
   print "1. In the source sample (renamed subs), run 'sample_source()'"
   print '2. Copy the src_data = "XXXXX...XXXX" string (if too long, will be in the "full_hash" global => store it into a file)'
   print "3. In the dest sample, paste it (or read the file and store it in the src_data global)"
   print "4. In the dest sample, load the script and run 'sample_dest()'"
   
help()
