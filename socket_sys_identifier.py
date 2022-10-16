# Binary Ninja Network System Call Plugin
# author: Robbie Heine
# 	email: robbieheine@gmail.com
#	github: @Robster4911
# description:
#	Scans a binary for all network system calls and adds a comment to describe the syscall and the arguments passed to it.


import binaryninja as bn

# globally defined arrays
sock_domain = ["UNIX", "LOCAL", "INET", "AX25", "IPX", "APPLETALK", "X25", "INET6", "DECnet", "KEY", "NETLINK", "PACKET", "RDS", "PPPOX", "LLC", "IB", "MPLS", "CAN", "TIPC", "BLUETOOTH", "ALG", "VSOCK", "KCM", "XDP"]
sock_type = ["STREAM", "DGRAM", "SEQPACKET", "RAW", "RDM", "PACKET"]
shutdown_how = ["RD", "WR", "RDWR"]

def run(bv):
	# iterate over each instruction in the binary
	for function in bv.functions:
		for code in function.low_level_il:
			for instruction in code:
				if instruction.operation == bn.LowLevelILOperation.LLIL_SYSCALL:
					note = "" # comment to be appended

					# grab syscall from rax
					syscall_num = instruction.get_reg_value('rax').value

					# rip needed to resolve pointer addresses
					# binja sets addresses all relative to 0x400000, or 4,194,304 in base 10
					# by including the binja offset, clicking on the value in the comment in
					# the UI will jump you to that spot in memory
					rip = instruction.get_reg_value('rip').value + 4194304

					# grab register values for the syscall arguments
					arg1 = instruction.get_reg_value('rdi').value
					arg2 = instruction.get_reg_value('rsi').value
					arg3 = instruction.get_reg_value('rdx').value
					arg4 = instruction.get_reg_value('r10').value
					arg5 = instruction.get_reg_value('r8').value
					arg6 = instruction.get_reg_value('r9').value

					# switch to handle the different syscalls
					if syscall_num == 41:
						# socket
						note = "SYSCALL :: socket(domain: AF_{}, type: SOCK_{}, protocol: {})".format(sock_domain[arg1], sock_type[arg2], str(arg3))
					elif syscall_num == 42:
						# connect
						note = "SYSCALL :: connect(sockfd: {}, *sockaddr: {}, addrlen: {})".format(arg1, hex(rip + arg2), arg3)
					elif syscall_num == 43:
						# accept
						note = "SYSCALL :: accept(sockfd: {}, *sockaddr: {}, *addrlen: {})".format(arg1, hex(rip + arg2), hex(rip + arg3))
					elif syscall_num == 44:
						# sendto
						note = "SYSCALL :: sendto(sockfd: {}, *buffer: {}, length: {}, flags: {}, *sockaddr: {}, *addrlen: {})".format(arg1, hex(rip + arg2), arg3, arg4, hex(rip + arg5), hex(rip + arg6))
					elif syscall_num == 45:
						# recvfrom
						note = "SYSCALL :: recvfrom(sockfd: {}, *buffer: {}, length: {}, flags: {}, *sockaddr: {}, *addrlen: {}}".format(arg1, hex(rip + arg2), arg3, arg4, hex(rip + arg5), hex(rip + arg6))
					elif syscall_num == 46:
						# sendmsg
						note = "SYSCALL :: sendmsg(sockfd: {}, *msgheader: {}, flags: {})".format(arg1, hex(rip + arg2), arg3)
					elif syscall_num == 47:
						# recvmsg
						note = "SYSCALL :: recvmsg(sockfd: {}, *msgheader: {}, flags: {})".format(arg1, hex(rip + arg2), arg3)
					elif syscall_num == 48:
						# shutdown
						note = "SYSCALL :: shutdown(sockfd: {}, how: SHUT_{})".format(arg1, shutdown_how[arg2])
					elif syscall_num == 49:
						# bind
						note = "SYSCALL :: bind(sockfd: {}, *socketaddr: {}, addrlen: {})".format(arg1, hex(rip + arg2), arg3)
					elif syscall_num == 50:
						# listen
						note = "SYSCALL :: listen(sockfd: {}, backlog: {})".format(arg1, arg2)
					# append the comment
					function.set_comment_at(instruction.address, note)
