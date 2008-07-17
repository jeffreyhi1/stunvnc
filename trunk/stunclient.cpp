
StunClient::StunClient()
{
}

StunClient::~StunClient()
{
}

int StunClient::GetSocket()
{
}

int StunClient::Init()
{
}

int StunClient::DetectNATType()
{
	
}

int StunClient::DectStepOne()
{
    t_stun_message binding_request;
    t_stun_message response;

    int err;
   
    //we create a  STUN Binding request
    if (create_stun_binding_request(&binding_request) < 0)
    {
		log("test1:unable to create message\n");
		return -1;
    }
    
	log("NOTICE:Starting TEST1\n");    
    err = send_rcv_msg_over_udp(&binding_request,&response);
	log("NOTICE:TEST1 finished\n");

    if (err < 0)
	{
	    if (err == -2)	//no response
		{
		    log("test1:no response\n");
		    return NO_RESPONSE;
		}
		else return err;
	}
    
    if (response.header.msg_type != MSG_TYPE_BINDING_RESPONSE)
    {
		log("test1:unespected response:%x\n", response.header.msg_type);
		return -6;
    }
    
    memcpy(msg,&(response),sizeof(t_stun_message));
	return RESPONSE_OK;
}



//sendinf and waiting for a response on UDP
int StunClient::send_rcv_msg_over_udp(t_stun_message *req, t_stun_message *response );
{
}

int StunClient::create_stun_binding_request(t_stun_message *msg)
{
	t_stun_header header;

	memset(msg,0,sizeof(t_stun_message));
    if (get_rand128(&tid) < 0) 
    {
    	log("ERROR:Cannot obtain RANDOMNESS\n");
	return -1;
    }
    if (create_stun_header(MSG_TYPE_BINDING_REQUEST,0, tid, &header) < 0) return -2;
    
     log("NOTICE:Created message with id %x-%x\n",tid.bytes[0],tid.bytes[1]);
    msg->header = header;
    return 1;
}

//it created the header of the message.
int StunClient::create_stun_header(t_uint16 msg_type, t_uint16 msg_len, t_uint128 tid,t_stun_header *header)
{
    header->msg_type = msg_type;
    header->msg_len = msg_len;
    memcpy(header->tid.bytes,tid.bytes,16);
    return 1;
}

int StunClient::get_rand128(t_uint128 *tid)
{
    static int init = 0;
    long int v[16];
    char *tmp;
    int i;
#ifdef WIN32
   int r1,r2,ret;
#endif

    if (init == 0)
    {
#ifndef WIN32
	srandom(time(0));
#else
	srand(time(0));
#endif

	init = 1;
    }
    for(i=0;i<16;i++)
	{
#ifndef WIN32
	v[i]=random();
#else
   	r1 = rand();
	r2 = rand()
   	v[i] = (r1<<16) + r2;
#endif
	}
    //a take the 4th byte from everyone
    for(i=0;i<16;i++)
	{
	    tmp = (char *)&(v[i]);
	    tid->bytes[i] = tmp[4];
	}
    return 1;	
}



































