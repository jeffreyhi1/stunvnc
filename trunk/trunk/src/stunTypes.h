/*
 * Copyright (C) 2001-2003 iptel.org/FhG
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#ifndef __stun_types_h
#define __stun_types_h

//tpes definitions
typedef unsigned char t_uint8;
typedef unsigned short t_uint16;
typedef unsigned int t_uint32;
typedef struct { unsigned char bytes[16];} t_uint128;


//stun types


#define UNDERSTAND_ATTRIBUTES	11 //0xB

//attributte types
#define  MAPPED_ADDRESS			0x0001
#define  RESPONSE_ADDRESS		0x0002
#define  CHANGE_REQUEST			0x0003
#define  SOURCE_ADDRESS			0x0004
#define  CHANGED_ADDRESS		0x0005
#define  USERNAME			0x0006
#define  PASSWORD			0x0007
#define  MESSAGE_INTEGRITY		0x0008
#define  ERROR_CODE			0x0009
#define  UNKNOWN_ATTRIBUTES		0x000A
#define  REFLECTED_FROM			0x000B



//anny attribute with a less or equal value must be undestood
#define  MANDATORY_LIMIT		0x7FFF

#define UNDERSTAND_MSG_TYPES			6
//message types
#define 	MSG_TYPE_BINDING_REQUEST			0x0001
#define 	MSG_TYPE_BINDING_RESPONSE			0x0101
#define 	MSG_TYPE_BINDING_ERROR_RESPONSE			0x0111
#define 	MSG_TYPE_SHARED_SECRET_REQUEST			0x0002
#define 	MSG_TYPE_SHARED_SECRET_RESPONSE			0x0102
#define 	MSG_TYPE_SHARED_SECRET_ERROR_RESPONSE		0x0112

//headerul
//#pragma pack(1)
typedef	struct
{
	t_uint16	msg_type;
	t_uint16	msg_len;
	t_uint128	tid;
}t_stun_header;

typedef	struct
{
	t_uint16	type;
	t_uint16	len;
}t_stun_attr_header;


#define 	IPv4FAMILY	0x01

struct mapped_address
    {
	t_stun_attr_header	header;
	t_uint8		unused;
	t_uint8		family;
	t_uint16	port;
	t_uint32	address;
    };

typedef	struct mapped_address	t_stun_mapped_address;
typedef	struct mapped_address	t_stun_response_address;
typedef	struct mapped_address	t_stun_changed_address;
typedef	struct mapped_address	t_stun_source_address;
typedef struct mapped_address	t_stun_reflected_from;

#define CHANGE_IP_FLAG		0x4 //is bit 29	0xffffffff
#define	CHANGE_PORT_FLAG	0x2 //is bit 30
typedef	struct
	{
	    t_stun_attr_header	header;
	    t_uint32		value;
	}			t_stun_change_request;

typedef	struct
	{
	    t_stun_attr_header	header;
	    t_uint8		hmac[20];
	}			t_stun_message_integrity;//trebuie sa fie ultimul

#define MAX_STRING_LEN	256//4*?
//#define MIN_USERNAME_LEN	4
//#define MIN_PASSWORD_LEN	16


struct	string_attr
    {
	t_stun_attr_header	header;
	char			value[MAX_STRING_LEN];//used for user and password
	unsigned int		len;
    };
typedef	struct string_attr	t_stun_username;
typedef	struct string_attr	t_stun_password;

#define MAX_UNKNOWN_ATTRIBUTES	20//2*, must be multiple of 2

typedef	struct
    {
	t_stun_attr_header	header;
	t_uint16		attr[MAX_UNKNOWN_ATTRIBUTES];
	unsigned int		attr_number;
    }				t_stun_unknown_attributes;
typedef struct
    {
	t_stun_attr_header	header;
	t_uint16		unused;//full of 0, actually we need 21 de bits off 0
	t_uint8			clas;	//first 5 bits must be 0
	t_uint8			number;
	char			reason[MAX_STRING_LEN];
	int 			reason_len;
    }				t_stun_error_code;

//message types
typedef	struct
    {
	char is_response_address;
	char is_change_request;
	char is_username;
	char is_message_integrity;
	t_stun_response_address		response_address;
	t_stun_change_request		change_request;
	t_stun_username			username;
	t_stun_message_integrity	message_integrity;
    }				t_stun_bind_req;
typedef	struct
    {
	char is_mapped_address;
	char is_source_address;
	char is_changed_address;
	char is_message_integrity;
	char is_reflected_from;
	t_stun_mapped_address		mapped_address;
	t_stun_source_address		source_address;
	t_stun_changed_address		changed_address;
	t_stun_message_integrity	message_integrity;
	t_stun_reflected_from		reflected_from;
    }				t_stun_bind_resp;
typedef	struct
    {
	char is_error_code;
	char is_unknown_attributes;
	t_stun_error_code		error_code;
	t_stun_unknown_attributes	unknown_attributes;
    }				t_stun_bind_err_resp;

typedef	struct
    {
#ifdef WIN32
		char dummy;
#endif
    }				t_stun_shared_req;
typedef struct
    {
	char is_username;
	char is_password;
	t_stun_username			username;
	t_stun_password			password;
    }				t_stun_shared_resp;
typedef	struct
    {
	char is_error_code;
	char is_unknown_attributes;
	t_stun_error_code		error_code;
	t_stun_unknown_attributes	unknown_attributes;
    }				t_stun_shared_err_resp;

#define MAX_MESSAGE_SIZE	65535 //BUF_SIZE //65535

#include "ip_addr.h"
typedef enum {UDP=1,TLS}	t_stun_protocol;
typedef struct
    {
	int 			len;
	char 			*pos;//current parsing position
	char 			buff[MAX_MESSAGE_SIZE];//should I use dynamic?
	int 			buff_len;
	t_stun_header		header;

	union
	    {
		t_stun_bind_req			req;
		t_stun_bind_resp		resp;
		t_stun_bind_err_resp		err_resp;
		t_stun_shared_req		shared_req;
		t_stun_shared_resp		shared_resp;
		t_stun_shared_err_resp		shared_err_resp;
	    }u;

	t_stun_protocol			protocol;
	union sockaddr_union		src;
	union sockaddr_union		original_src;//in case I change the SRC based on an RESPONSE ADDRESS
	union sockaddr_union		dst;
    }t_stun_message;
//#pragma pack(4)

#define STUN_HEADER_LEN 			20
#define STUN_ADDRESS_LEN 			8
#define STUN_CHANGE_REQUEST_LEN		4
#define STUN_MESSAGE_INTEGRITY_LEN	20
#define STUN_ATTR_HEADER_LEN		4

#define STUN_ERROR_420_REASON		"(Unknown Attribute): The server did not understand a mandatory attribute in the request."
#define STUN_ERROR_420_REASON_LEN	88

#define STUN_ERROR_432_REASON		"(Missing Username): The Binding Request contained a MESSAGE-INTEGRITY attribute, but not a USERNAME attribute.Both must be present for integrity checks."
#define STUN_ERROR_432_REASON_LEN	152

#define STUN_ERROR_430_REASON		"(Stale Credentials): The Binding Request did contain a MESSAGE-INTEGRITY attribute, but it used a shared secret that has expired. The client should obtain a new shared secret and try again.   "
#define STUN_ERROR_430_REASON_LEN	192

#define STUN_ERROR_431_REASON		"(Integrity Check Failure): The Binding Request contained a MESSAGE-INTEGRITY attribute, but the HMAC failed verification. This could be a sign of a potential attack, or client implementation error.  "
#define STUN_ERROR_431_REASON_LEN	200

#define STUN_ERROR_400_REASON		"(Bad Request): The request was malformed. The client should not retry the request without modification from the previous attempt.   "
#define STUN_ERROR_400_REASON_LEN	132

#define STUN_ERROR_500_REASON		"(Server Error)The server has suffered a temporary error.The client should try again."
#define STUN_ERROR_500_REASON_LEN	84


#define USERNAME_PREFIX_LEN	4
#define USERNAME_LEN		12 //4+2+4+2
#define PASSWORD_LEN		STUN_MESSAGE_INTEGRITY_LEN

#endif

