#ifndef __STUN_CLIENT_H__
#define __STUN_CLIENT_H__

#define NO_RESPONSE 	0
#define IP_SAME		1
#define IP_NOT_SAME	2
#define RESPONSE_OK 3


class StunInfo
{
public:
	int sockClient;
	string strSrvIP;
	ushort usSrvPort;			

	string strClientIP;
	ushort strclientPort;
	
};

class StunClient
{
public:
	StunClient();
	~StunClient();
	
	int GetSocket(){reutrn socket;};
	
private:
	int Init();
	int DectStepOne();
	int DetectNATType();
	int send_rcv_msg_over_udp(t_stun_message *req,t_stun_message *response );
	int create_stun_binding_request(t_stun_message *msg);

	StunInfo m_stunInfo;
	t_uint128 tid;

};
#endif
