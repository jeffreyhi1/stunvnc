#include "stun_create.h"
#include "common.h"
#include "globals.h"
#include "udp_server.h"
#include <stdlib.h>
#include <time.h>
#include "ip_addr.h"
#include <string.h>
#include "utils.h"
#include "shm.h"
#include "server.h"

#if 0
int get_rand16(int min,int max,t_uint16 *r)
{
    static int init = 0;
    int res;
    
    if (init == 0)
    {
#ifndef WIN32
	srandom(time(0));
#else
	srand(time(0));
#endif
	init = 1;
    }
    res = min+(int)(max*rand()/(RAND_MAX+1.0));
    
    *r = (t_uint16)res;
    return 1;
}



int get_rand128(t_uint128 *tid)
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
   r1 = rand();r2 = rand();ret = (r1<<16) + r2;
   v[i] = ret;
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


//it created the header of the message.
int create_stun_header(t_uint16 msg_type,t_uint16 msg_len,t_uint128 tid,t_stun_header *header)
{
    header->msg_type = msg_type;
    header->msg_len = msg_len;
    memcpy(header->tid.bytes,tid.bytes,16);
    return 1;
}

//it transforms from a structure to a char vector.
int format_stun_header(char *buf,unsigned int len,t_stun_header *header)
{
    char *pos;
    t_uint16 temp;
    
    pos = buf;
    temp = htons(header->msg_type);memcpy(pos,&temp,2);pos+=2;
    temp = htons(header->msg_len);memcpy(pos,&temp,2);pos+=2;
    memcpy(pos,header->tid.bytes,16);pos+=16;
    
    return pos-buf;
}

//the values for port,and address are in host order
int create_stun_address(t_uint16 type,t_uint8 family,t_uint16 port,t_uint32 address,void *addr)
{
    struct mapped_address *ma;
    ma = (struct mapped_address *)addr;
    
    ma->unused = 0;
    ma->family = family;
    ma->port = port;
    ma->address = address;
    
    ma->header.type = type;
    ma->header.len = STUN_ADDRESS_LEN;
    
    return 1;
}

int format_stun_address(char *buf,unsigned int len,void *addr)
{
    struct mapped_address *ma;
    char *pos;
    t_uint16 ts;
    t_uint32 tl;
    
    ma = (struct mapped_address *)addr;
    pos = buf;
    ts = htons(ma->header.type);
    memcpy(pos,&ts,2);pos+=2;
    ts = htons(ma->header.len);
    memcpy(pos,&ts,2);pos+=2;
    *pos = ma->unused;pos += 1;
    *pos = ma->family;pos += 1;
    ts = htons(ma->port);
    memcpy(pos,&ts,2);pos+=2;
    tl = htonl(ma->address);
    memcpy(pos,&tl,4);pos+=4;
    
    return pos-buf;
}

int create_stun_change_request(int change_ip,int change_port,t_stun_change_request *cr)
{
    
    cr->value = 0;
    if (change_ip)
        cr->value = cr->value | CHANGE_IP_FLAG;
    if (change_port)
	cr->value = cr->value | CHANGE_PORT_FLAG;
    cr->header.type = CHANGE_REQUEST;
    cr->header.len = STUN_CHANGE_REQUEST_LEN;
    return 1;
}

int format_stun_change_request(char *buf,unsigned int len,t_stun_change_request *cr)
{
    char *pos;
    t_uint16 ts;
    t_uint32 tl;
    
    pos = buf;
    ts = htons(cr->header.type);
    memcpy(pos,&ts,2);pos+=2;
    ts = htons(cr->header.len);
    memcpy(pos,&ts,2);pos+=2;
    tl = htonl(cr->value);
    memcpy(pos,&tl,4);pos+=4; /* bug here was +2 */
    
    return pos-buf;
}

//the algorithm is described in STUN RFC. Based on the ip, port, time,a seed, and the hmac of these  we generate a username
int generate_username(t_uint32 client_ip,t_uint16 port,char *hmac_key,unsigned int key_len,char **user,unsigned int *len)
{
    int i;
    t_uint16	r;
    t_uint16	minutes;
    char *username;
    char ulen;
    time_t t;
    char	hmac[STUN_MESSAGE_INTEGRITY_LEN];
    
    ulen = USERNAME_PREFIX_LEN+2+4+2+STUN_MESSAGE_INTEGRITY_LEN;
    if (ulen % 4 != 0) return -1;
    username = NULL;
    username = (char *)malloc(ulen);
    if (username ==NULL) return -2;
    
    for(i=0;i<USERNAME_PREFIX_LEN;i++)
    {
	get_rand16(32,126,&r);
	username[i] = (char)r;
    }
    t = time(0);
    minutes = t%1200;
    memcpy(username+USERNAME_PREFIX_LEN,&minutes,2);
    memcpy(username+USERNAME_PREFIX_LEN+2,&client_ip,4);
    memcpy(username+USERNAME_PREFIX_LEN+6,&port,2);
    if (compute_hmac((char *)hmac,username,USERNAME_PREFIX_LEN+8,hmac_key,key_len) < 0) 
    {
	free(username);
	return -2;
    }
    memcpy(username+USERNAME_PREFIX_LEN+8,hmac,STUN_MESSAGE_INTEGRITY_LEN);
    
    *user = username;
    *len = ulen;
    return 1;
}

// the password is a sha1 based on the username
int generate_password(char *username,unsigned int ulen,char *another_key,unsigned int key_len,char **pass,unsigned int *len)
{
    char	hmac[STUN_MESSAGE_INTEGRITY_LEN];
    char *password;
    
    *len = STUN_MESSAGE_INTEGRITY_LEN;
    password = NULL;
    password = (char *)malloc(*len);
    if (password == NULL)	return -1;
    if (compute_hmac((char *)hmac,username,ulen,another_key,key_len) < 0) 
    {
	free(password);
	return -2;
    }
    memcpy(password,hmac,STUN_MESSAGE_INTEGRITY_LEN);
    
    *pass = password;
    return 1;
}

// if attr_value is NULL we generate the username based on the algorithm, else we use the received one
int create_stun_username(char *attr_value,unsigned int len,t_uint32 client_ip,t_uint16 port,t_stun_username *username)
{
    char *uname;
    unsigned int ulen;
    
    //it is used to signal the server what password to use for authentication
    if (attr_value == NULL) 
    {
	if (generate_username(client_ip,port,username_hmac_key,strlen(username_hmac_key),&uname,&ulen)<0)	return -1;
	username->len = ulen;
	memcpy(username->value,uname,ulen);
	free(uname);
    }
    else
    {
	if (len % 4 != 0) return -2;
	username->len = len;
	memcpy(username->value,attr_value,len);
    }

    username->header.type = USERNAME;
    username->header.len = username->len;
    return 1;
}

int format_stun_username(char *buf,unsigned int len,t_stun_username *username)
{
    char *pos;
    t_uint16 ts;
    pos = buf;
    
    ts = htons(username->header.type);
    memcpy(pos,&ts,2);pos+=2;
    ts = htons(username->header.len);
    memcpy(pos,&ts,2);pos+=2;
    memcpy(pos,(char *)username->value,username->len);pos+=username->len;
    
    return pos-buf;
        
}

//if attr_value is NULL we generate the password, else we use the one received
int create_stun_password(char *attr_value,unsigned int len,t_stun_username *username,t_stun_password *password)//apare doar in shared secret response
{
    char *pass;
    unsigned int passlen;
    
    if (attr_value == NULL) //generam noi
    {
	//if (generate_string_attr(PASSWORD,&pass,&passlen)<0)	return -1;
	if (generate_password(username->value,username->len,another_private_key,strlen(another_private_key),&pass,&passlen)<0)	return -1;
	password->len = passlen;
	memcpy(password->value,pass,passlen);
	free(pass);
    }
    else
    {
	if (len % 4 != 0) return -2;
	password->len = len;
	memcpy(password->value,attr_value,len);
    }

    password->header.type = PASSWORD;
    password->header.len = password->len;
    
    return 1;
}

int format_stun_password(char *buf,unsigned int len,t_stun_password *password)
{
    char *pos;
    t_uint16 ts;
    
    pos = buf;
    ts = htons(password->header.type);
    memcpy(pos,&ts,2);pos+=2;
    ts = htons(password->header.len);
    memcpy(pos,&ts,2);pos+=2;
    memcpy(pos,(char *)password->value,password->len);pos+=password->len;
    
    return pos-buf;

}

int create_stun_unknown_attributes(t_uint16 *attributes,unsigned int len,t_stun_unknown_attributes *ua)
{
    int i;
    
    if (len+4 > MAX_UNKNOWN_ATTRIBUTES) return -1;
    
    for(i=0;i<len;i++)
	{
	    ua->attr[i] = attributes[i];
	}
    ua->attr_number = len;
    for (;ua->attr_number%2 != 0;)
	{
	    //we add them
	    ua->attr[ua->attr_number++]=ua->attr[ua->attr_number-1];
	}
    if (log_1) LOG("create_stun_unknown_attributes:au->attr_len is %u\n",ua->attr_number);
    ua->header.len = 2*ua->attr_number;// 2 should divide the number of them
    ua->header.type = UNKNOWN_ATTRIBUTES;
    if (ua->header.len % 4 ) 
	if (log_1) LOG("create_stun_unknown_attributtes:len not modulo 4\n");
    return 1;
}

int format_stun_unknown_attributes(char *buf,unsigned int len,t_stun_unknown_attributes *ua)
{
    char *pos;
    int i;
    t_uint16 ts;
    
    pos = buf;
    ts = htons(ua->header.type);
    memcpy(pos,&ts,2);pos+=2;
    ts = htons(ua->header.len);
    memcpy(pos,&ts,2);pos+=2;
    for(i=0;i<ua->attr_number;i++)
    {
	ts = htons(ua->attr[i]);
	memcpy(pos,&ts,2);pos+=2;
    }
    
    return pos-buf;
}
int create_stun_error_code(t_uint8 clas,t_uint8 number,char *reason,unsigned int reason_len,t_stun_error_code *err)
{
    if (reason_len + 4 > MAX_STRING_LEN)	return -1;
    err->unused = 0;
    err->clas = clas;
    err->number = number;
    err->reason_len = reason_len;
    memcpy(err->reason,reason,reason_len);
    for (;err->reason_len%4 != 0;)
	{
	    //we add spaces till we have a multiple of 4
	    err->reason[err->reason_len++]=' ';
	}
	
    err->header.len = err->reason_len+4;
    err->header.type = ERROR_CODE;
    return 1;
}

int format_stun_error_code(char *buf,int len,t_stun_error_code *err)
{
    char *pos = buf;
    t_uint16 ts;
    
    ts = htons(err->header.type);
    memcpy(pos,&ts,2);pos+=2;
    ts = htons(err->header.len);
    memcpy(pos,&ts,2);pos+=2;
    ts = htons(err->unused);
    memcpy(pos,&ts,2); pos+=2;
    *pos = err->clas;pos+=1;
    *pos = err->number;pos+=1;
    memcpy(pos,(char *)err->reason,err->reason_len);pos+=err->reason_len;
    
    return pos-buf;
}

int create_stun_message_integrity(char *msg,unsigned int len,char *key,unsigned int key_len,t_stun_message_integrity *mi)
{
    if (len % 4 != 0)
    {
	if (log_1) LOG("create_stun_message_integrity:len not modulo 4\n");
	return -1;
    }
    if (compute_hmac(mi->hmac,msg,len,key,key_len) < 0) return -1;
    
    mi->header.type = MESSAGE_INTEGRITY;
    mi->header.len = STUN_MESSAGE_INTEGRITY_LEN;
    return 1;	
}

int format_stun_message_integrity(char *buf,unsigned int len,t_stun_message_integrity *mi)
{
    char *pos = buf;
    t_uint16 ts;
    
    ts = htons(mi->header.type);
    memcpy(pos,&ts,2);pos+=2;
    ts = htons(mi->header.len);
    memcpy(pos,&ts,2);pos+=2;
    memcpy(pos,(char *)mi->hmac,20);pos+=20;
    return 1;
}

//when we create a message we only fill in the mandatory attributes
int create_stun_binding_request(t_stun_message *msg)
{
    t_stun_header header;
    t_uint128 tid;
    
    
    memset(msg,0,sizeof(t_stun_message));
    if (get_rand128(&tid) < 0) 
    {
	if (log_1) LOG("ERROR:Cannot obtain RANDOMNESS\n");
	return -1;
    }
    if (create_stun_header(MSG_TYPE_BINDING_REQUEST,0,tid,&header) < 0) return -2;
    
    if (log_1) LOG("NOTICE:Created message with id %x-%x\n",tid.bytes[0],tid.bytes[1]);
    msg->header = header;
    return 1;
}

int format_stun_binding_request(t_stun_message *msg)
{
    int res;
    
    msg->pos = msg->buff;    
    msg->len = MAX_MESSAGE_SIZE;
    msg->buff_len=0;
    
    //we jump over the first 20 bytes,the header, and we return later, after we know the total length
    res = STUN_HEADER_LEN;
    msg->buff_len += res;
    msg->len -= res;
    msg->pos = msg->buff+msg->buff_len;
    msg->header.msg_len = 0;
    if (msg->u.req.is_response_address)
    {
	    res = format_stun_address(msg->pos,msg->len,&msg->u.req.response_address);    
	    msg->buff_len += res;
	    msg->len -= res;
	    msg->pos = msg->buff+msg->buff_len;
	    msg->header.msg_len += msg->u.req.response_address.header.len + STUN_ATTR_HEADER_LEN;
    }
    
    if (msg->u.req.is_change_request)
    {
	    res = format_stun_change_request(msg->pos,msg->len,&msg->u.req.change_request);    
	    msg->buff_len += res;
	    msg->len -= res;
	    msg->pos = msg->buff+msg->buff_len;
	    msg->header.msg_len += msg->u.req.change_request.header.len + STUN_ATTR_HEADER_LEN;
    }

    if (msg->u.req.is_username)
    {
	    res = format_stun_username(msg->pos,msg->len,&msg->u.req.username);    
	    msg->buff_len += res;
	    msg->len -= res;
	    msg->pos = msg->buff+msg->buff_len;
	    msg->header.msg_len += msg->u.req.username.header.len + STUN_ATTR_HEADER_LEN;
    }

    if (msg->u.req.is_message_integrity)
    {
	    res = format_stun_message_integrity(msg->pos,msg->len,&msg->u.req.message_integrity);    
	    msg->buff_len += res;
	    msg->len -= res;
	    msg->pos = msg->buff+msg->buff_len;
	    msg->header.msg_len += msg->u.req.message_integrity.header.len + STUN_ATTR_HEADER_LEN;
    }
    res = format_stun_header(msg->buff,STUN_HEADER_LEN,&msg->header);    
    if (log_1) LOG("format_stun_binding_request:header->len=%u buff_len=%u\n",msg->header.msg_len,msg->buff_len);

    return 1;
}
//TODO:if the requestul contains USERNAME and MESSAGE_INTEGRITY i should add a MI
int create_stun_binding_response(t_stun_message *req,t_stun_message *msg)
{
    t_stun_header header;
    t_uint128 tid;
    unsigned int len;
    t_stun_mapped_address ma;
    t_stun_source_address sa;
    t_stun_changed_address ca;
    t_stun_reflected_from rf;
    t_uint16 port;
    t_uint32 address;
    char *pass;
    unsigned int plen;
    t_stun_message 		n;
    int 			adv;

    
    memset(msg,0,sizeof(t_stun_message));
    if (req == NULL)
    {
        if (get_rand128(&tid) < 0) return -1;
    }
    else tid = req->header.tid;
    if (create_stun_header(MSG_TYPE_BINDING_RESPONSE,0,tid,&header) < 0) return -2;
    msg->header = header;
    len = 0;
    //mandatory:mapped_address,source_address,changed_address,
    port = ntohs(req->original_src.sin.sin_port);
    memcpy(&address,&(req->original_src.sin.sin_addr),4);
    address = ntohl(address);
    if (create_stun_address(MAPPED_ADDRESS,IPv4FAMILY,port,address,&ma) < 0)	return -3;
    msg->u.resp.is_mapped_address = 1;
    msg->u.resp.mapped_address = ma;
    

    //?changed_address si source_address?
    if (req->u.req.is_change_request)
    {
	if (req->u.req.change_request.value & CHANGE_PORT_FLAG)
	    port = ntohs(bind_address_port->su.sin.sin_port);
	else port = ntohs(bind_address->su.sin.sin_port);
	
	if (req->u.req.change_request.value & CHANGE_IP_FLAG)
		memcpy(&address,&(alternate_address->su.sin.sin_addr),4);
	else memcpy(&address,&(bind_address->su.sin.sin_addr),4);
	address = ntohl(address);
    }
    else //we have no request to change ip or port 
    {
	port = ntohs(bind_address->su.sin.sin_port);
	memcpy(&address,&(bind_address->su.sin.sin_addr),4);
	address = ntohl(address);
    }

    if (create_stun_address(SOURCE_ADDRESS,IPv4FAMILY,port,address,&sa) < 0)	return -4;    
    msg->u.resp.is_source_address = 1;
    msg->u.resp.source_address = sa;


        port = ntohs(bind_address_port->su.sin.sin_port);
	memcpy(&address,&(alternate_address->su.sin.sin_addr),4);
	address = ntohl(address);
    if (create_stun_address(CHANGED_ADDRESS,IPv4FAMILY,port,address,&ca) < 0)	return -5;    
    msg->u.resp.is_changed_address = 1;
    msg->u.resp.changed_address = ca;
    
    /*	
    port = ntohs(bind_address->su.sin.sin_port);
    memcpy(&address,&(bind_address->su.sin.sin_addr),4);
    address = ntohl(address);
    if (create_stun_address(SOURCE_ADDRESS,IPv4FAMILY,port,address,&sa) < 0)	return -4;
    
    msg->u.resp.is_source_address = 1;
    msg->u.resp.source_address = sa;
    */
    
    //PAG11
    if (req->u.req.is_response_address)
    {
	//we create request_from, if we have a  username, because in it we save the inital address of the request  pag 11 STUN RFC
	if (req->u.req.is_username)
	{
	    //we get from  username the address and port of registration 
	    if (req->u.req.username.len != USERNAME_PREFIX_LEN+2+4+2+STUN_MESSAGE_INTEGRITY_LEN)
		return -2;
	    memcpy(&address,(req->u.req.username.value+USERNAME_PREFIX_LEN+2),4);
	    memcpy(&port,(req->u.req.username.value+USERNAME_PREFIX_LEN+6),2);
	}
	else
	{
    	    port = ntohs(req->original_src.sin.sin_port);
    	    memcpy(&address,&(req->original_src.sin.sin_addr),4);
    	    address = ntohl(address);
	}
	if (create_stun_address(REFLECTED_FROM,IPv4FAMILY,port,address,&rf) < 0)	return -4;
	msg->u.resp.is_reflected_from = 1;
	msg->u.resp.reflected_from = rf;
    }
    
    if ((req->u.req.is_username)&&(req->u.req.is_message_integrity))
    {
	//TODO:we add MI
	pass = NULL;
	plen = 0;
	if (obtain_password(req->u.req.username.value,req->u.req.username.len,&pass,&plen)<0)	return -5;//internal error
	if (plen == 0)
		    {
			//error  430,expired password
			    adv = create_stun_binding_error_response(4,30,STUN_ERROR_430_REASON,STUN_ERROR_430_REASON_LEN,req,&n);
			    adv = format_stun_binding_error_response(&n);
			    adv = udp_send(bind_address,(char *)n.buff,n.buff_len,&(req->original_src));
			    return -6;
		    }
	//pag 28:the buffer must be padded with 0 till it dvides with 64	    
	if (compute_hmac(msg->u.resp.message_integrity.hmac,msg->buff,msg->buff_len,pass,plen) < 0) 
		{
			    if (pass) free(pass);
			    return -102;//internal error
		}
	msg->u.resp.is_message_integrity = 1;
	if (pass) free(pass);
	
    }
    return 1;
}

int format_stun_binding_response(t_stun_message *msg)
{
    int res;
    
    msg->pos = msg->buff;    
    msg->len = MAX_MESSAGE_SIZE;
    msg->buff_len=0;
    
    //jumping over header
    res = STUN_HEADER_LEN;
    msg->buff_len += res;
    msg->len -= res;
    msg->pos = msg->buff+msg->buff_len;
    msg->header.msg_len = 0;
    
    if (msg->u.resp.is_mapped_address)
    {
	    res = format_stun_address(msg->pos,msg->len,&msg->u.resp.mapped_address);    
	    msg->buff_len += res;
	    msg->len -= res;
	    msg->pos = msg->buff+msg->buff_len;
	    msg->header.msg_len += msg->u.resp.mapped_address.header.len + STUN_ATTR_HEADER_LEN;
    }
    else return -1;//is mandatory
    if (msg->u.resp.is_changed_address)
    {
	    res = format_stun_address(msg->pos,msg->len,&msg->u.resp.changed_address);    
	    msg->buff_len += res;
	    msg->len -= res;
	    msg->pos = msg->buff+msg->buff_len;
	    msg->header.msg_len += msg->u.resp.mapped_address.header.len + STUN_ATTR_HEADER_LEN;
    }
    else return -2;// mandatory
    if (msg->u.resp.is_source_address)
    {
	    res = format_stun_address(msg->pos,msg->len,&msg->u.resp.source_address);    
	    msg->buff_len += res;
	    msg->len -= res;
	    msg->pos = msg->buff+msg->buff_len;
	    msg->header.msg_len += msg->u.resp.mapped_address.header.len + STUN_ATTR_HEADER_LEN;
    }
    else return -3;//mandatory
    if (msg->u.resp.is_reflected_from)
    {
	    res = format_stun_address(msg->pos,msg->len,&msg->u.resp.reflected_from);    
	    msg->buff_len += res;
	    msg->len -= res;
	    msg->pos = msg->buff+msg->buff_len;
	    msg->header.msg_len += msg->u.resp.mapped_address.header.len + STUN_ATTR_HEADER_LEN;
    }
    if (msg->u.resp.is_message_integrity)
    {
	    res = format_stun_message_integrity(msg->pos,msg->len,&msg->u.resp.message_integrity);    
	    msg->buff_len += res;
	    msg->len -= res;
	    msg->pos = msg->buff+msg->buff_len;
	    msg->header.msg_len += msg->u.resp.message_integrity.header.len + STUN_ATTR_HEADER_LEN;
    }
    
    //we return to the header
    res = format_stun_header(msg->buff,STUN_HEADER_LEN,&msg->header);    
    if (log_1) LOG("format_stun_binding_response:header->len=%u buff_len=%u\n",msg->header.msg_len,msg->buff_len);
    return 1;

}

int create_stun_binding_error_response(t_uint8 clas,t_uint8 number,char *reason,unsigned int reason_len,t_stun_message *req,t_stun_message *msg)
{
    t_stun_header header;
    t_uint128 tid;
    t_stun_error_code	err;
    
    memset(msg,0,sizeof(t_stun_message));
    if (req == NULL) 
    {
    	if (get_rand128(&tid) < 0) return -1;
    }
    else tid = req->header.tid;
    if (create_stun_header(MSG_TYPE_BINDING_ERROR_RESPONSE,0,tid,&header) < 0) return -2;
    msg->header = header;
    //mandatory:error code.
    if (create_stun_error_code(clas,number,reason,reason_len,&err) < 0) return -3;
    msg->u.err_resp.is_error_code = 1;
    msg->u.err_resp.error_code = err;    
//    if (log_1) LOG("create_stun_binding_error_response:header->len=%u err.header.len=%u buff_len=%u\n",msg->header.msg_len,err.header.len,msg->buff_len);
    
    return 1;
}

int format_stun_binding_error_response(t_stun_message	*msg)
{
    int res;
    msg->pos = msg->buff;    
    msg->len = MAX_MESSAGE_SIZE;
    msg->buff_len=0;
    
    res = STUN_HEADER_LEN;
    msg->buff_len += res;
    msg->len -= res;
    msg->pos = msg->buff+msg->buff_len;
    msg->header.msg_len = 0;
    
    if (msg->u.err_resp.is_error_code)
    {
	    res = format_stun_error_code(msg->pos,msg->len,&msg->u.err_resp.error_code);    
	    msg->buff_len += res;
	    msg->len -= res;
	    msg->pos = msg->buff+msg->buff_len;
	    msg->header.msg_len += msg->u.err_resp.error_code.header.len + STUN_ATTR_HEADER_LEN;
    }
    if (msg->u.err_resp.is_unknown_attributes)
    {
	    res = format_stun_unknown_attributes(msg->pos,msg->len,&msg->u.err_resp.unknown_attributes);    
	    msg->buff_len += res;
	    msg->len -= res;
	    msg->pos = msg->buff+msg->buff_len;
	    msg->header.msg_len += msg->u.err_resp.unknown_attributes.header.len + STUN_ATTR_HEADER_LEN;
    }
    res = format_stun_header(msg->buff,STUN_HEADER_LEN,&msg->header);    
    if (log_1) LOG("create_stun_binding_error_response:header->len=%u buff_len=%u\n",msg->header.msg_len,msg->buff_len);
    return 1;
}
int create_stun_shared_secret_request(t_stun_message *msg)
{
    t_stun_header header;
    t_uint128 tid;
    
    memset(msg,0,sizeof(t_stun_message));
    if (get_rand128(&tid) < 0) return -1;
    if (create_stun_header(MSG_TYPE_SHARED_SECRET_REQUEST,0,tid,&header) < 0) return -2;

    return 1;
}

int format_stun_shared_secret_request(t_stun_message *msg)
{
    int res;
    msg->pos = msg->buff;    
    msg->len = MAX_MESSAGE_SIZE;
    msg->buff_len=0;
    
    res = STUN_HEADER_LEN;
    msg->buff_len += res;
    msg->len -= res;
    msg->pos = msg->buff+msg->buff_len;
    msg->header.msg_len = 0;

    //nothing to add
    res = format_stun_header(msg->buff,STUN_HEADER_LEN,&msg->header);    
    if (log_1) LOG("create_stun_shared_secret_request:header->len=%u buff_len=%u\n",msg->header.msg_len,msg->buff_len);
    
    return 1;
}

int create_stun_shared_secret_response(t_stun_message *req,t_stun_message *msg)
{    
    t_stun_username username;
    t_stun_password password;
    t_uint32	client_ip;
    t_uint16	client_port;
    t_uint128  tid;
    t_stun_header header;
    shm_struct entry
    ;
    //TODO:contains only USERNAME and PASSWORD, send on TLS
    //there are valable at least 10 minutes,at most 30 de minutes
    //password must have at least 16 bytes
    //PAG13
    memset(msg,sizeof(t_stun_message),0);
    if (req == NULL)
    {
	if (get_rand128(&tid)<0) return -1;
    }
    else tid=req->header.tid;
    if (create_stun_header(MSG_TYPE_SHARED_SECRET_RESPONSE,0,tid,&header) < 0) return -2;
    msg->header = header;

    memcpy(&client_ip,&(req->original_src.sin.sin_addr),4);
    memcpy(&client_port,&(req->original_src.sin.sin_port),2);
    
    if (create_stun_username(NULL,0,client_ip,client_port,&username)<0) return -1;
    if (create_stun_password(NULL,0,&username,&password)<0) return -2;
    msg->u.shared_resp.is_username = 1;
    msg->u.shared_resp.username = username;
    msg->u.shared_resp.is_password = 1;
    msg->u.shared_resp.password = password;
    
    //TODO:add password and username to the shared memory
    memcpy(entry.username,username.value,USERNAME_LEN);
    memcpy(entry.password,password.value,PASSWORD_LEN);
    entry.expire = time(0) + EXPIRE;
#ifdef USE_TLS
    if (add_entry(&entry) < 0)	return -101;//not enough memory,we shall respond with a 500
#else
    return -101;
#endif
    return 1;
}

int format_stun_shared_secret_response(t_stun_message *msg)
{
    int res;
    msg->pos = msg->buff;    
    msg->len = MAX_MESSAGE_SIZE;
    msg->buff_len=0;
    
    res = STUN_HEADER_LEN;
    msg->buff_len += res;
    msg->len -= res;
    msg->pos = msg->buff+msg->buff_len;
    msg->header.msg_len = 0;
    
    if (msg->u.shared_resp.is_username)
    {
	    res = format_stun_username(msg->pos,msg->len,&msg->u.shared_resp.username);    
	    msg->buff_len += res;
	    msg->len -= res;
	    msg->pos = msg->buff+msg->buff_len;
	    msg->header.msg_len += msg->u.shared_resp.username.header.len + STUN_ATTR_HEADER_LEN;
    }
    else return -1;//mandatory
    if (msg->u.shared_resp.is_password)
    {
	    res = format_stun_password(msg->pos,msg->len,&msg->u.shared_resp.password);    
	    msg->buff_len += res;
	    msg->len -= res;
	    msg->pos = msg->buff+msg->buff_len;
	    msg->header.msg_len += msg->u.shared_resp.password.header.len + STUN_ATTR_HEADER_LEN;
    }
    else return -2;//mandatory
    res = format_stun_header(msg->buff,STUN_HEADER_LEN,&msg->header);    
    if (log_1) LOG("format_stun_shared_secret_response:header->len=%u buff_len=%u\n",msg->header.msg_len,msg->buff_len);

    return 1;
}
int create_stun_shared_secret_error_response(t_uint8 clas,t_uint8 number,char *reason,unsigned int reason_len,t_stun_message *req,t_stun_message *msg)
{
    t_stun_header header;
    t_uint128 tid;
    t_stun_error_code	err;
    
    memset(msg,0,sizeof(t_stun_message));
    if (req == NULL) 
    {
	if (get_rand128(&tid) < 0) return -1;
    }
    else tid = req->header.tid;
    if (create_stun_header(MSG_TYPE_SHARED_SECRET_ERROR_RESPONSE,0,tid,&header) < 0) return -2;
    msg->header = header;
    //mandatory:error code.
    if (create_stun_error_code(clas,number,reason,reason_len,&err) < 0) return -3;
    msg->u.err_resp.is_error_code = 1;
    msg->u.err_resp.error_code = err;    

    return 1;
}

int format_stun_shared_secret_error_response(t_stun_message *msg)
{
    int res;
    msg->pos = msg->buff;    
    msg->len = MAX_MESSAGE_SIZE;
    msg->buff_len=0;
    
    res = STUN_HEADER_LEN;
    msg->buff_len += res;
    msg->len -= res;
    msg->pos = msg->buff+msg->buff_len;
    msg->header.msg_len = 0;
    
    if (msg->u.err_resp.is_error_code)
    {
	    res = format_stun_error_code(msg->pos,msg->len,&msg->u.err_resp.error_code);    
	    msg->buff_len += res;
	    msg->len -= res;
	    msg->pos = msg->buff+msg->buff_len;
	    msg->header.msg_len += msg->u.err_resp.error_code.header.len + STUN_ATTR_HEADER_LEN;
    }
    if (msg->u.err_resp.is_unknown_attributes)
    {
	    res = format_stun_unknown_attributes(msg->pos,msg->len,&msg->u.err_resp.unknown_attributes);    
	    msg->buff_len += res;
	    msg->len -= res;
	    msg->pos = msg->buff+msg->buff_len;
	    msg->header.msg_len += msg->u.err_resp.unknown_attributes.header.len + STUN_ATTR_HEADER_LEN;
    }
    res = format_stun_header(msg->buff,STUN_HEADER_LEN,&msg->header);    
    if (log_1) LOG("format_stun_binding_error_response:header->len=%u buff_len=%u\n",msg->header.msg_len,msg->buff_len);
    return 1;        
}
#endif

