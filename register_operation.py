def do_xor(value_in, xor_val):
	xor = value_in ^ xor_val
	if (xor >= 256) or (xor < 0):
		xor = "{:02x}".format(xor & 0xffffffff)[-2:]
		xor = int(xor,16)
	return xor

def do_add(value_in, add_val):
	add = value_in + add_val
	if (add >= 256) or (add < 0):
		add = "{:02x}".format(add & 0xffffffff)[-2:]
		add = int(add, 16)
	return add

def do_sub(value_in, sub_val):
	sub = value_in - sub_val
	if (sub >= 256) or (sub < 0):
		sub = "{:02x}".format(sub & 0xffffffff)[-2:]
		sub = int(sub, 16)
	return sub