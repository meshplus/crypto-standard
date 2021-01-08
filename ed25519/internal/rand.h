/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_RAND_H
# define HEADER_RAND_H

#ifdef  __cplusplus
extern "C" {
#endif

int RAND_bytes(unsigned char *buf, int num);


#ifdef  __cplusplus
}
#endif

#endif
