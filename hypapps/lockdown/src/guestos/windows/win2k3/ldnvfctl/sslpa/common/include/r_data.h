/**
   r_data.h


   Copyright (C) 1999-2000 RTFM, Inc.
   All Rights Reserved

   This package is a SSLv3/TLS protocol analyzer written by Eric Rescorla
   <ekr@rtfm.com> and licensed by RTFM, Inc.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. All advertising materials mentioning features or use of this software
      must display the following acknowledgement:

      This product includes software developed by Eric Rescorla for
      RTFM, Inc.

   4. Neither the name of RTFM, Inc. nor the name of Eric Rescorla may be
      used to endorse or promote products derived from this
      software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY ERIC RESCORLA AND RTFM, INC. ``AS IS'' AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY SUCH DAMAGE.

   $Id: r_data.h,v 1.2 2000/10/17 16:09:59 ekr Exp $


   ekr@rtfm.com  Wed Feb 10 14:18:19 1999
 */


#ifndef _r_data_h
#define _r_data_h

typedef struct Data_ {
     UCHAR *data;
     int len;
} Data;

int r_data_create PROTO_LIST((Data **dp,UCHAR *d,int l));
int r_data_alloc PROTO_LIST((Data **dp, int l));
int r_data_make PROTO_LIST((Data *dp, UCHAR *d,int l));
int r_data_destroy PROTO_LIST((Data **dp));
int r_data_copy PROTO_LIST((Data *dst,Data *src));
int r_data_zfree PROTO_LIST((Data *d));
int r_data_compare PROTO_LIST((Data *d1,Data *d2));

#define INIT_DATA(a,b,c) (a).data=b; (a).len=c
#define ATTACH_DATA(a,b) (a).data=b; (a).len=sizeof(b)
#define ZERO_DATA(a) (a).data=0; (a).len=0

#endif
