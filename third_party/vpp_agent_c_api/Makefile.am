
ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libvpp-agent-api.la

libvpp_agent_api_la_SOURCES = \
	vpp/model/rpc/rpc.grpc-c.c \
	vpp/model/ipsec/ipsec.grpc-c.c \
	vpp/model/interfaces/interfaces.grpc-c.c \
	vpp/model/punt/punt.grpc-c.c \
	vpp/model/l3/l3.grpc-c.c \
	vpp/model/acl/acl.grpc-c.c \
	vpp/model/bfd/bfd.grpc-c.c \
	vpp/model/l2/l2.grpc-c.c \
	vpp/model/l4/l4.grpc-c.c \
	vpp/model/nat/nat.grpc-c.c \
	vpp/model/stn/stn.grpc-c.c \
	linux/model/interfaces/interfaces.grpc-c.c \
	linux/model/l3/l3.grpc-c.c

libvpp_agent_api_la_LIBADD = -lgpr -lgrpc -lprotobuf-c -lprotobuf -lprotobuf-c
